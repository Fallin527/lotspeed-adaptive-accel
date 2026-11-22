package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// 实测场景的回归测试: 一条走 docker bridge 的 socket (26.66MB, minrtt 277ms) 和一条
// 走 ens3 的 (1.31MB, minrtt 1ms)。过滤前 far 档会带着 95% 的 acked 参与决策 ——
// 那正是生产日志里 "band -> far ... util=0.02 ... C_hat=19.1 Mbps" 的成因。
func TestSSBandsExcludesOtherInterfaces(t *testing.T) {
	rows := parseSSRows(`0 0 45.149.156.93:443 172.18.0.4:8897
	 lotspeed rtt:277.5/3.0 minrtt:277.13 bytes_acked:27960240 segs_out:20000
0 0 45.149.156.93:443 172.68.211.12:18172
	 lotspeed rtt:1.5/0.5 minrtt:1.034 bytes_acked:1374219 segs_out:1000`, 0)
	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2", len(rows))
	}
	if rows[0].dst != "172.18.0.4:8897" || rows[1].dst != "172.68.211.12:18172" {
		t.Fatalf("dst 未被带出: %q / %q", rows[0].dst, rows[1].dst)
	}

	rc := &routeCache{iface: "ens3", m: map[string]routeEnt{}}
	rc.lookup = func(ip string) string {
		if ip == "172.18.0.4" {
			return "br-7860d40690c0"
		}
		return "ens3"
	}
	if rc.via("172.18.0.4:8897") {
		t.Error("docker bridge 上的 socket 不该通过过滤")
	}
	if !rc.via("172.68.211.12:18172") {
		t.Error("走 ens3 的 socket 必须通过过滤")
	}
}

// fail-open: 查不到路由时必须 include, 不能把样本丢光让控制器瞎掉。
func TestRouteCacheFailsOpen(t *testing.T) {
	rc := &routeCache{iface: "ens3", m: map[string]routeEnt{}}
	rc.lookup = func(string) string { return "" } // 模拟 exec 失败
	if !rc.via("1.2.3.4:80") {
		t.Error("路由查不到时必须 include (fail-open)")
	}
	// 没配 iface 时也不过滤
	rc2 := &routeCache{m: map[string]routeEnt{}}
	rc2.lookup = func(string) string { return "lo" }
	if !rc2.via("1.2.3.4:80") {
		t.Error("iface 为空时没有过滤依据, 必须 include")
	}
}

// v6 地址的 host 剥离: 不能按第一个冒号切 (地址内部全是冒号)。
func TestHostOfHandlesV6(t *testing.T) {
	for in, want := range map[string]string{
		"172.68.211.12:18172": "172.68.211.12",
		"[2001:db8::1]:443":   "2001:db8::1",
		"[::1]:80":            "::1",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q)=%q want %q", in, got, want)
		}
	}
}

// 档边界抖动必须被迟滞压住: 一条压在 250ms 边界上的单 socket far 档, 不能每两拍
// 就把控制信号从 intercontinental 抢走 (实测过它在 util=0.13 时触发了假 latch)。
func TestBandSwitchNeedsConfirmation(t *testing.T) {
	s := newTestShaper()
	s.pickedBand = "intercontinental"
	inter := ssTargetStat{socks: 4, acked: 1e9, minRttP50Ms: 180, queueDelayMs: 5}
	far := ssTargetStat{socks: 1, acked: 1e6, minRttP50Ms: 255, queueDelayMs: 93}
	bands := map[string]ssTargetStat{"intercontinental": inter, "far": far}

	// far 有排队会赢 pickBand, 但前 bandConfirmCycles-1 拍必须仍用 intercontinental。
	for i := 1; i < bandConfirmCycles; i++ {
		st, band := pickBand(bands)
		if band != "far" {
			t.Fatalf("cycle %d: pickBand 应选 far (有排队), 得 %q", i, band)
		}
		_ = st
		s.bandHiN++
		if old, ok := bands[s.pickedBand]; !ok || old.socks == 0 || s.bandHiN >= bandConfirmCycles {
			t.Fatalf("cycle %d: 不该这么早切换 (bandHiN=%d)", i, s.bandHiN)
		}
	}
	// 第 bandConfirmCycles 拍才允许接管
	s.bandHiN++
	if s.bandHiN < bandConfirmCycles {
		t.Fatalf("bandHiN=%d 应已达 %d", s.bandHiN, bandConfirmCycles)
	}
}

// 回归 (2026-11 SG1/JP1 OOM 事故): 存进 routeCache 的 key/dev 绝不能是调用方
// 大缓冲区的视图。事故形态: hostOf(dst) 的切片视图直接当 key 写进 rc.m, 每个
// 唯一 IP 钉死它首次入表那一拍的整份 `ss -tin` 输出 (代理出口上单次数百 KB),
// 数万个 churn IP 累积出 GB 级泄漏。这里用 unsafe.StringData 做指针域判断:
// clone 过的 key/dev 必然落在调用方缓冲区之外 —— 防的是机理本身, 不是表象。
func TestRouteCacheKeysDecoupledFromCallerBuffer(t *testing.T) {
	// 1.5MB 合成 ss 输出; 从中切一行作为 dst, 与 parseSSRows -> ssBands -> via()
	// 的真实传参形态一致 (r.dst = strings.Fields 的 f[3], 是大字符串的视图)。
	var b strings.Builder
	for i := 0; i < 20000; i++ {
		b.WriteString("lotspeed rtt:12.3/1.0 minrtt:11.0 bytes_acked:9999 segs_out:99\n")
	}
	b.WriteString("0 0 10.0.0.1:443 203.0.113.7:5201\n")
	big := b.String()
	off := strings.Index(big, "203.0.113.7:5201")
	if off < 0 {
		t.Fatal("合成缓冲里找不到目标行")
	}
	dst := big[off : off+len("203.0.113.7:5201")]

	// lookup 的返回值同样造成视图 (模拟 routeDev 返回 f[i+1] 的形态)。
	devBuf := "1.2.3.4 via 10.0.0.1 dev ens3 src 10.0.0.1"
	dvOff := strings.Index(devBuf, "ens3")
	dv := devBuf[dvOff : dvOff+len("ens3")]

	rc := &routeCache{iface: "ens3", m: map[string]routeEnt{}}
	rc.lookup = func(string) string { return dv }
	if !rc.via(dst) {
		t.Fatal("ens3 上的 socket 必须通过过滤")
	}

	inRange := func(p, lo uintptr, n int) bool { return p >= lo && p < lo+uintptr(n) }
	bigLo := uintptr(unsafe.Pointer(unsafe.StringData(big)))
	devLo := uintptr(unsafe.Pointer(unsafe.StringData(devBuf)))

	rc.mu.Lock()
	defer rc.mu.Unlock()
	if len(rc.m) != 1 {
		t.Fatalf("entries=%d want 1", len(rc.m))
	}
	for k, e := range rc.m {
		if k != "203.0.113.7" {
			t.Fatalf("key=%q want 203.0.113.7", k)
		}
		if inRange(uintptr(unsafe.Pointer(unsafe.StringData(k))), bigLo, len(big)) {
			t.Fatal("key 仍钉在调用方 ss 缓冲区里 — store() 必须 strings.Clone (SG1 OOM 根因)")
		}
		if e.dev != "ens3" {
			t.Fatalf("dev=%q want ens3", e.dev)
		}
		if inRange(uintptr(unsafe.Pointer(unsafe.StringData(e.dev))), devLo, len(devBuf)) {
			t.Fatal("dev 仍钉在 lookup 缓冲区里 — store() 必须 strings.Clone")
		}
	}
}

// 上界 + 过期清扫: 代理 churn 场景下"只增不删 (TTL 只在命中时检查)"曾让缓存
// 无界膨胀。超 routeCacheMax 后必须先清过期、仍满再随机淘汰; 过期条目不能
// 永远躺在表里。
func TestRouteCacheBoundAndSweep(t *testing.T) {
	rc := &routeCache{iface: "ens3", m: map[string]routeEnt{}}
	rc.lookup = func(string) string { return "ens3" }
	for i := 0; i < routeCacheMax+1000; i++ {
		if !rc.via(fmt.Sprintf("10.%d.%d.%d:443", (i>>16)&0xff, (i>>8)&0xff, i&0xff)) {
			t.Fatal("lookup 返回 ens3 的 dst 必须全部通过")
		}
	}
	if n := rc.size(); n > routeCacheMax {
		t.Fatalf("上界失效: %d > %d 条", n, routeCacheMax)
	}
	// 全部回拨到过期, 再触发一次写入: sweep 必须清光过期条目。
	rc.mu.Lock()
	for k := range rc.m {
		rc.m[k] = routeEnt{dev: "ens3", at: time.Now().Add(-2 * routeCacheTTL)}
	}
	rc.mu.Unlock()
	rc.via("192.0.2.9:80")
	if n := rc.size(); n > 1 {
		t.Fatalf("过期清扫未生效: 残留 %d 条 (want <=1)", n)
	}
}

// 并发安全 (-race 下覆盖 store/sweep/warnOnce/negative-cache 全部路径):
// store/sweep 是 2026-11 修复轮新引入的写路径, 必须证明多 goroutine 扇出调用
// via() 时仍然成立 —— warned 原来就是裸读写, 那是个潜伏的数据竞争。
func TestRouteCacheConcurrentVia(t *testing.T) {
	rc := &routeCache{iface: "ens3", m: map[string]routeEnt{}}
	rc.lookup = func(ip string) string {
		if strings.HasSuffix(ip, ".9") {
			return "" // 覆盖 fail-open + warnOnce + negative-cache 路径
		}
		return "ens3"
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				rc.via(fmt.Sprintf("10.%d.%d.%d:443", 64+g, i>>8, i&0xff))
			}
		}(g)
	}
	wg.Wait()
	if n := rc.size(); n > routeCacheMax {
		t.Fatalf("并发下上界失效: %d 条", n)
	}
}

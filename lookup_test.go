package mdns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	testService  = "_consul-aiur._tcp.local."
	testInstance = "consul-citadel._consul-aiur._tcp.local."
	testHost     = "citadel.local."
	testV4       = "192.168.7.1"
	testV6       = "fd00::7:1"
)

func hdr(name string, t uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: 120}
}

func ptr(service, instance string) dns.RR {
	return &dns.PTR{Hdr: hdr(service, dns.TypePTR), Ptr: instance}
}

func srv(instance, target string, port uint16) dns.RR {
	return &dns.SRV{Hdr: hdr(instance, dns.TypeSRV), Target: target, Port: port}
}

func txt(instance string) dns.RR {
	return &dns.TXT{Hdr: hdr(instance, dns.TypeTXT), Txt: []string{""}}
}

func a(name, ip string) dns.RR {
	return &dns.A{Hdr: hdr(name, dns.TypeA), A: net.ParseIP(ip)}
}

func aaaa(name, ip string) dns.RR {
	return &dns.AAAA{Hdr: hdr(name, dns.TypeAAAA), AAAA: net.ParseIP(ip)}
}

func reply(answer []dns.RR, extra ...dns.RR) *dns.Msg {
	return &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: answer, Extra: extra}
}

func asks(qs []question) map[question]bool {
	m := make(map[question]bool)
	for _, q := range qs {
		m[q] = true
	}
	return m
}

// A responder that answers each question with only the record asked for
// (systemd-resolved): PTR first, then the follow-ups the client must send.
// The host answers A but not AAAA, so the entry is handed out with IPv4
// once the AAAA question has gone unanswered twice.
func TestLookupFollowsUpLikeRFC6763(t *testing.T) {
	l := newLookup(testService)
	t0 := time.Now()
	at := func(s float64) time.Time { return t0.Add(time.Duration(s * float64(followUpResend))) }

	l.handle(reply([]dns.RR{ptr(testService, testInstance)}), nil)
	if got := l.ready(at(0)); len(got) != 0 {
		t.Fatalf("handed out after the PTR alone: %v", got)
	}
	got := asks(l.followUps(at(0)))
	if len(got) != 2 || !got[question{testInstance, dns.TypeSRV}] || !got[question{testInstance, dns.TypeTXT}] {
		t.Fatalf("follow-ups %v, want SRV and TXT for the instance", got)
	}

	l.handle(reply([]dns.RR{srv(testInstance, testHost, 8301)}), nil)
	l.handle(reply([]dns.RR{txt(testInstance)}), nil)
	got = asks(l.followUps(at(0.1)))
	if len(got) != 2 || !got[question{testHost, dns.TypeA}] || !got[question{testHost, dns.TypeAAAA}] {
		t.Fatalf("follow-ups %v, want A and AAAA for %s", got, testHost)
	}

	l.handle(reply([]dns.RR{a(testHost, testV4)}), nil)
	if got := l.ready(at(0.2)); len(got) != 0 {
		t.Fatalf("handed out before the AAAA question settled: %v", got)
	}
	got = asks(l.followUps(at(1.1)))
	if len(got) != 1 || !got[question{testHost, dns.TypeAAAA}] {
		t.Fatalf("follow-ups %v, want the AAAA question again", got)
	}
	if got := l.ready(at(1.5)); len(got) != 0 {
		t.Fatalf("handed out before the second AAAA question timed out: %v", got)
	}
	done := l.ready(at(2.1))
	if len(done) != 1 {
		t.Fatalf("not handed out once AAAA went unanswered: %v", done)
	}
	e := done[0]
	if e.Name != testInstance || e.Host != testHost || e.Port != 8301 || !e.AddrV4.Equal(net.ParseIP(testV4)) || e.AddrV6 != nil {
		t.Fatalf("entry %+v", e)
	}
	if more := l.followUps(at(10)); len(more) != 0 {
		t.Fatalf("follow-ups after hand-out: %v", more)
	}
	if again := l.ready(at(10)); len(again) != 0 {
		t.Fatalf("entry handed out twice")
	}
}

// Both families answered: the entry goes out at once, whichever came first.
func TestLookupBothFamilies(t *testing.T) {
	l := newLookup(testService)
	now := time.Now()
	l.handle(reply([]dns.RR{ptr(testService, testInstance)}), nil)
	l.handle(reply([]dns.RR{srv(testInstance, testHost, 8301)}, txt(testInstance)), nil)
	l.followUps(now)
	l.handle(reply([]dns.RR{aaaa(testHost, testV6)}), nil)
	if got := l.ready(now); len(got) != 0 {
		t.Fatalf("handed out with only the AAAA answer: %v", got)
	}
	l.handle(reply([]dns.RR{a(testHost, testV4)}), nil)
	done := l.ready(now)
	if len(done) != 1 || done[0].AddrV4 == nil || done[0].AddrV6 == nil {
		t.Fatalf("got %v, want one entry with both families", done)
	}
}

// A responder that adds SRV, TXT and both addresses to its PTR answer
// (avahi) completes the entry at once, with no follow-up.
func TestLookupCompleteInOneReply(t *testing.T) {
	l := newLookup(testService)
	now := time.Now()
	l.handle(reply([]dns.RR{ptr(testService, testInstance)},
		srv(testInstance, testHost, 8301), txt(testInstance), a(testHost, testV4), aaaa(testHost, testV6)), nil)
	if qs := l.followUps(now); len(qs) != 0 {
		t.Fatalf("follow-ups %v for a complete entry", qs)
	}
	if done := l.ready(now); len(done) != 1 {
		t.Fatalf("got %v, want one entry", done)
	}
}

// Records ahead of their PTR in the same message still count.
func TestLookupPTRAfterOtherRecords(t *testing.T) {
	l := newLookup(testService)
	l.handle(reply([]dns.RR{srv(testInstance, testHost, 8301), txt(testInstance), a(testHost, testV4), aaaa(testHost, testV6)},
		ptr(testService, testInstance)), nil)
	if done := l.ready(time.Now()); len(done) != 1 {
		t.Fatalf("got %v, want one entry", done)
	}
}

// Other services' records on the link never make entries (hashicorp/mdns#96).
func TestLookupIgnoresOtherServices(t *testing.T) {
	l := newLookup(testService)
	other := "Living-Room._airplay._tcp.local."
	l.handle(reply([]dns.RR{ptr("_airplay._tcp.local.", other)},
		srv(other, "living-room.local.", 7000), txt(other), a("living-room.local.", "192.168.4.28")), nil)
	if len(l.entries) != 0 {
		t.Fatalf("other service accepted: %v", l.entries)
	}
	if qs := l.followUps(time.Now()); len(qs) != 0 {
		t.Fatalf("follow-ups %v for another service", qs)
	}
}

// DNS names compare case-insensitively.
func TestLookupNameCase(t *testing.T) {
	l := newLookup("_Consul-Aiur._TCP.local.")
	l.handle(reply([]dns.RR{ptr(testService, "Consul-Citadel._consul-aiur._tcp.local.")},
		srv(testInstance, "CITADEL.local.", 8301), txt(testInstance), a(testHost, testV4), aaaa(testHost, testV6)), nil)
	if done := l.ready(time.Now()); len(done) != 1 {
		t.Fatalf("got %v, want one entry", done)
	}
}

// A follow-up is resent once after followUpResend, then given up.
func TestLookupFollowUpLimits(t *testing.T) {
	l := newLookup(testService)
	now := time.Now()
	l.handle(reply([]dns.RR{ptr(testService, testInstance)}), nil)
	if n := len(l.followUps(now)); n != 2 {
		t.Fatalf("first round: %d questions, want 2", n)
	}
	if n := len(l.followUps(now.Add(followUpResend / 2))); n != 0 {
		t.Fatalf("resent after %v: %d questions", followUpResend/2, n)
	}
	if n := len(l.followUps(now.Add(followUpResend))); n != 2 {
		t.Fatalf("second round: %d questions, want 2", n)
	}
	if n := len(l.followUps(now.Add(5 * followUpResend))); n != 0 {
		t.Fatalf("third round: %d questions, want none", n)
	}
}

// Two instances in one message both go out.
func TestLookupTwoInstancesInOneMessage(t *testing.T) {
	l := newLookup(testService)
	fleet := "consul-fleet._consul-aiur._tcp.local."
	l.handle(reply([]dns.RR{ptr(testService, testInstance), ptr(testService, fleet)},
		srv(testInstance, testHost, 8301), txt(testInstance), a(testHost, testV4), aaaa(testHost, testV6),
		srv(fleet, "fleet.local.", 8301), txt(fleet), a("fleet.local.", "192.168.5.1"), aaaa("fleet.local.", "fd00::5:1")), nil)
	if done := l.ready(time.Now()); len(done) != 2 {
		t.Fatalf("got %d entries, want 2", len(done))
	}
}

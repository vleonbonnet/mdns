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
func TestLookupFollowsUpLikeRFC6763(t *testing.T) {
	l := newLookup(testService)
	now := time.Now()

	if done := l.handle(reply([]dns.RR{ptr(testService, testInstance)}), nil); len(done) != 0 {
		t.Fatalf("complete after the PTR alone: %v", done)
	}
	got := asks(l.followUps(now))
	want := []question{{testInstance, dns.TypeSRV}, {testInstance, dns.TypeTXT}}
	if len(got) != len(want) || !got[want[0]] || !got[want[1]] {
		t.Fatalf("follow-ups %v, want SRV and TXT for the instance", got)
	}

	l.handle(reply([]dns.RR{srv(testInstance, testHost, 8301)}), nil)
	l.handle(reply([]dns.RR{txt(testInstance)}), nil)
	got = asks(l.followUps(now.Add(followUpResend)))
	if !got[question{testHost, dns.TypeA}] || !got[question{testHost, dns.TypeAAAA}] {
		t.Fatalf("follow-ups %v, want A and AAAA for %s", got, testHost)
	}

	done := l.handle(reply([]dns.RR{a(testHost, "192.168.7.1")}), nil)
	if len(done) != 1 {
		t.Fatalf("not complete after the address: %v", done)
	}
	e := done[0]
	if e.Name != testInstance || e.Host != testHost || e.Port != 8301 || !e.AddrV4.Equal(net.ParseIP("192.168.7.1")) {
		t.Fatalf("entry %+v", e)
	}
	if more := l.followUps(now.Add(10 * followUpResend)); len(more) != 0 {
		t.Fatalf("follow-ups after completion: %v", more)
	}
}

// A responder that adds SRV, TXT and the address to its PTR answer (avahi)
// completes the entry at once, with no follow-up.
func TestLookupCompleteInOneReply(t *testing.T) {
	l := newLookup(testService)
	done := l.handle(reply([]dns.RR{ptr(testService, testInstance)},
		srv(testInstance, testHost, 8301), txt(testInstance), a(testHost, "192.168.7.1")), nil)
	if len(done) != 1 {
		t.Fatalf("got %v, want one complete entry", done)
	}
	if qs := l.followUps(time.Now()); len(qs) != 0 {
		t.Fatalf("follow-ups %v for a complete entry", qs)
	}
	if again := l.handle(reply([]dns.RR{ptr(testService, testInstance)},
		srv(testInstance, testHost, 8301), txt(testInstance), a(testHost, "192.168.7.1")), nil); len(again) != 0 {
		t.Fatalf("entry returned twice")
	}
}

// Records ahead of their PTR in the same message still count.
func TestLookupPTRAfterOtherRecords(t *testing.T) {
	l := newLookup(testService)
	done := l.handle(reply([]dns.RR{srv(testInstance, testHost, 8301), txt(testInstance), a(testHost, "192.168.7.1")},
		ptr(testService, testInstance)), nil)
	if len(done) != 1 {
		t.Fatalf("got %v, want one complete entry", done)
	}
}

// Other services' records on the link never make entries (hashicorp/mdns#96).
func TestLookupIgnoresOtherServices(t *testing.T) {
	l := newLookup(testService)
	other := "Living-Room._airplay._tcp.local."
	done := l.handle(reply([]dns.RR{ptr("_airplay._tcp.local.", other)},
		srv(other, "living-room.local.", 7000), txt(other), a("living-room.local.", "192.168.4.28")), nil)
	if len(done) != 0 || len(l.entries) != 0 {
		t.Fatalf("other service accepted: %v %v", done, l.entries)
	}
	if qs := l.followUps(time.Now()); len(qs) != 0 {
		t.Fatalf("follow-ups %v for another service", qs)
	}
}

// DNS names compare case-insensitively.
func TestLookupNameCase(t *testing.T) {
	l := newLookup("_Consul-Aiur._TCP.local.")
	done := l.handle(reply([]dns.RR{ptr(testService, "Consul-Citadel._consul-aiur._tcp.local.")},
		srv(testInstance, "CITADEL.local.", 8301), txt(testInstance), a(testHost, "192.168.7.1")), nil)
	if len(done) != 1 {
		t.Fatalf("got %v, want one complete entry", done)
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

// Two instances in one message both complete.
func TestLookupTwoInstancesInOneMessage(t *testing.T) {
	l := newLookup(testService)
	fleet := "consul-fleet._consul-aiur._tcp.local."
	done := l.handle(reply([]dns.RR{ptr(testService, testInstance), ptr(testService, fleet)},
		srv(testInstance, testHost, 8301), txt(testInstance), a(testHost, "192.168.7.1"),
		srv(fleet, "fleet.local.", 8301), txt(fleet), a("fleet.local.", "192.168.5.1")), nil)
	if len(done) != 2 {
		t.Fatalf("got %d complete entries, want 2", len(done))
	}
}

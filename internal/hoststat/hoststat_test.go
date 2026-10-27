package hoststat

import "testing"

const ifconfigOut = `em0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 08:00:27:aa:bb:cc
	inet 10.61.220.18 netmask 0xffffff00 broadcast 10.61.220.255
bridge1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 58:9c:fc:10:ff:a1
	member: tap0 flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>
	member: epair3a flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>
	member: em0 flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>
tap0: flags=1008943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	description: vm1-nic0
	options=80000<LINKSTATE>
	ether 58:9c:fc:10:3c:7e
epair3a: flags=1008943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	description: web1-epair3
	ether 02:a1:b2:c3:d4:0a
epair4a: flags=1008943<UP,BROADCAST,RUNNING> metric 0 mtu 1500
	description: web10-epair4
	ether 02:a1:b2:c3:d4:0b
`

const netstatOut = `Name      Mtu Network       Address              Ipkts Ierrs Idrop     Ibytes    Opkts Oerrs     Obytes  Coll
em0      1500 <Link#1>      08:00:27:aa:bb:cc   500000     0     0  700000000   400000     0   90000000     0
em0         - 10.61.220.0/24 10.61.220.18      450000     -     -  650000000   390000     -   88000000     -
lo0     16384 <Link#2>      lo0                     10     0     0       1000       10     0       1000     0
tap0     1500 <Link#5>      58:9c:fc:10:3c:7e     1200     0     0     150000     3400     1     4100000     0
epair3a  1500 <Link#6>      02:a1:b2:c3:d4:0a      777     0     0      88888      999     0     123456     0
`

func TestMatchNICs(t *testing.T) {
	ifs, cnt := parseIfconfig(ifconfigOut), parseNetstat(netstatOut)
	n := matchNICs("web1", ifs, cnt)
	if len(n) != 1 || n[0].Name != "epair3a" || n[0].Bridge != "bridge1" || n[0].RxBytes != 123456 || n[0].TxBytes != 88888 || !n[0].Up {
		t.Fatalf("web1: %+v", n)
	}
	v := matchNICs("vm1", ifs, cnt)
	if len(v) != 1 || v[0].Name != "tap0" || v[0].MAC != "58:9c:fc:10:3c:7e" || v[0].RxBytes != 4100000 || v[0].Errs != 1 {
		t.Fatalf("vm1: %+v", v)
	}
	if c := cnt["lo0"]; c.ibytes != 1000 {
		t.Errorf("lo0 without address: %+v", c)
	}
}

func TestParsePsAndDataset(t *testing.T) {
	p := parsePs(" 1.5  2048  10240\n 0,5 1024 4096\n\n")
	if p.Count != 2 || p.CPU != 2 || p.RSS != 3072*1024 || p.VSZ != 14336*1024 {
		t.Fatalf("%+v", p)
	}
	d, ok := parseDataset("zroot/jails/web1\t1000\t2000\t900\t/usr/jails/jails-data/web1-data\n")
	if !ok || d.Name != "zroot/jails/web1" || d.Avail != 2000 || d.Mountpoint != "/usr/jails/jails-data/web1-data" {
		t.Fatalf("%+v", d)
	}
}

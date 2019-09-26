package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"sync"

	"log"

	"github.com/cespare/xxhash"
	pb "github.com/prometheus/alertmanager/nflog/nflogpb"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql"

	"github.com/matttproud/golang_protobuf_extensions/pbutil"
)

type state map[string]*pb.MeshEntry

var verbose = flag.Bool("verbose", false, "log debug messages")
var address = flag.String("address", ":59599", "address")

// stateKey returns a string key for a log entry consisting of the group key
// and receiver.
func stateKey(k string, r *pb.Receiver) string {
	return fmt.Sprintf("%s:%s", k, receiverKey(r))
}

func receiverKey(r *pb.Receiver) string {
	return fmt.Sprintf("%s/%s/%d", r.GroupName, r.Integration, r.Idx)
}

func main() {
	flag.Parse()

	prometheus.Register(&Exporter{})

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(*address, nil))

}

func decodeState(r io.Reader) (state, error) {
	st := state{}
	for {
		var e pb.MeshEntry
		_, err := pbutil.ReadDelimited(r, &e)
		if err == nil {
			if e.Entry == nil || e.Entry.Receiver == nil {
				return nil, errors.New("oops")
			}
			st[stateKey(string(e.Entry.GroupKey), e.Entry.Receiver)] = &e
			continue
		}
		if err == io.EOF {
			break
		}
		return nil, err
	}
	return st, nil

}

func hashAlert(a *types.Alert) uint64 {
	const sep = '\xff'

	b := getHashBuffer()
	defer putHashBuffer(b)

	names := make(model.LabelNames, 0, len(a.Labels))

	for ln := range a.Labels {
		names = append(names, ln)
	}
	sort.Sort(names)

	for _, ln := range names {
		b = append(b, string(ln)...)
		b = append(b, sep)
		b = append(b, string(a.Labels[ln])...)
		b = append(b, sep)
	}

	hash := xxhash.Sum64(b)

	return hash
}

var hashBuffers = sync.Pool{}

func getHashBuffer() []byte {
	b := hashBuffers.Get()
	if b == nil {
		return make([]byte, 0, 1024)
	}
	return b.([]byte)
}

func putHashBuffer(b []byte) {
	b = b[:0]
	//lint:ignore SA6002 relax staticcheck verification.
	hashBuffers.Put(b)
}

func getAmHash() ([]uint64, error) {
	hashes := []uint64{}
	resp, err := http.Get("http://127.0.0.1:9093/api/v2/alerts")
	if err != nil {
		return hashes, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return hashes, err
	}
	var x []*types.Alert
	err = json.Unmarshal(body, &x)
	if err != nil {
		return hashes, err
	}

	for _, alert := range x {
		hashes = append(hashes, hashAlert(alert))
	}
	return hashes, nil
}

func getNflogHash(file string) (state, error) {
	r, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	return decodeState(r)
}

func gauge(l labels.Labels, hash string) *prometheus.GaugeVec {
	var x []string
	for _, n := range l {
		x = append(x, n.Name)
	}
	return prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("ALERTS_IN_NFLOG_NOT_FIRING_%s", hash),
			Help: "Alerts in NFLOG but no longer firing.",
		},
		x,
	)
}

type Exporter struct {
}

func (e *Exporter) Describe(c chan<- *prometheus.Desc) {
	//prometheus.DescribeByCollect(e, c)
}

func (*Exporter) Collect(c chan<- prometheus.Metric) {
	currentAlerts, err := getAmHash()
	if err != nil {
		fmt.Println(err)
		return
	}

	s, err := getNflogHash(flag.Arg(0))
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, mesh := range s {
		for _, a := range mesh.Entry.FiringAlerts {
			var found bool
			for _, u := range currentAlerts {
				if u == a {
					found = true
				}
			}
			var l labels.Labels
			var found2 bool
			for i := 0; i < len(mesh.Entry.GroupKey); i++ {
				var err error
				l, err = promql.ParseMetric(string(mesh.Entry.GroupKey[len(mesh.Entry.GroupKey)-i:]))
				if err == nil {
					found2 = true
					break
				}
			}
			if found2 && !found {
				g := gauge(l, fmt.Sprintf("%v_%v_count", hashBytes(mesh.Entry.GroupKey), a))
				g.With(l.Map()).Inc()
				g.Collect(c)
				g2 := gauge(l, fmt.Sprintf("%v_%v_timestamp_seconds", hashBytes(mesh.Entry.GroupKey), a))
				g2.With(l.Map()).Set(float64(mesh.Entry.Timestamp.UnixNano()) / 1e9)
				g2.Collect(c)
				g3 := gauge(l, fmt.Sprintf("%v_%v_expires_at", hashBytes(mesh.Entry.GroupKey), a))
				g3.With(l.Map()).Set(float64(mesh.ExpiresAt.UnixNano()) / 1e9)
				g3.Collect(c)
			}
		}
	}
}

func hashBytes(s []byte) uint32 {
	h := fnv.New32a()
	h.Write(s)
	return h.Sum32()
}

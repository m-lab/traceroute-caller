// Package tracer takes care of all interactions with the traceroute
// tools, currently only scamper.  This package supports two types
// of traceroutes among the many that scamper can run: MDA and regular:
//   - MDA traceroute (tracelb) finds load balanced paths between two
//     addresses by varying the first 4 bytes of the transport header, but
//     keeping the first 4 bytes constant when probing consecutive hops.
//     the -P parameter to tracelb says what type of probes to send,
//     and while the names have overlap with the -P parameter to trace,
//     they mean different things.
//   - Regular traceroute using Paris algorithm (trace -P icmp-paris)
//     finds a single path between two addresses by keeping the first 4
//     bytes of the transport header constant.
// See scamper's man page for more details.
package tracer

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// QueryCostHistogram tracks the costs of dedup and other queries.
	traceTimeHistogram = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "trace_time_seconds",
			Help: "scamper trace time in seconds",
			Buckets: []float64{
				// These are log spaced bins, 6 bins per decade
				1, 1.47, 2.15, 3.16, 4.64, 6.81,
				10, 14.7, 21.5, 31.6, 46.4, 68.1,
				100, 147, 215, 316, 464, 681,
				1000, 1470, 2150, 3160, 4640, 6810,
			},
		},
		// Outcome, e.g. success, failure
		[]string{"outcome"},
	)

	tracesPerformed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "traces_performed_total",
			Help: "The number of calls to the external trace routine",
		},
		[]string{"type"},
	)
	tracesInProgress = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "traces_in_progress",
			Help: "The number of traces currently being run",
		},
		[]string{"type"},
	)
	crashedTraces = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "traces_crashed_total",
			Help: "The number of traces that have crashed",
		},
		[]string{"type"},
	)
	tracesNotPerformed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "traces_skipped_total",
			Help: "The number of traces that have not been performed because there was an error cached",
		},
		[]string{"type"},
	)
	tracerCacheErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "traces_error_caching_total",
			Help: "The number of traces that were supposed to be gotten from the cache but could not be",
		},
		[]string{"type", "error"},
	)
	// hostname of the current machine. Only call os.Hostname once, because the
	// result should never change.
	hostname string
)

// Metadata is the first line of the traceroute .jsonl file.
//
// TODO: move this struct to ETL parser.
type Metadata struct {
	UUID                    string
	TracerouteCallerVersion string
	CachedResult            bool
	CachedUUID              string
}

func init() {
	var err error
	hostname, err = os.Hostname()
	rtx.Must(err, "failed to call os.Hostname")
}

// extractUUID returns the UUID in the metadata line of a traceroute.
//
// TODO: Eliminate the need to unmarshal data we marshaled in the first place.
func extractUUID(metaline []byte) string {
	var md Metadata
	err := json.Unmarshal(metaline, &md)
	if err != nil {
		log.Println("failed to parse metaline:", string(metaline))
		return ""
	}
	return md.UUID
}

// createMetaline returns what the first line of the .jsonl output file
// should be. Parameter isCache indicates whether this meta line is for an
// original traceroute or a cached traceroute, and parameter cachedUUID is
// the original traceroute if isCache is 1.
func createMetaline(uuid string, isCache bool, cachedUUID string) []byte {
	meta := Metadata{
		UUID:                    uuid,
		TracerouteCallerVersion: prometheusx.GitShortCommit,
		CachedResult:            isCache,
		CachedUUID:              cachedUUID,
	}
	metaJSON, _ := json.Marshal(meta)
	return append(metaJSON, byte('\n'))
}

// createDatePath returns a string with date in format prefix/yyyy/mm/dd/ after
// creating a directory of the same name.
func createDatePath(outputPath string, t time.Time) (string, error) {
	dir := outputPath + "/" + t.Format("2006/01/02") + "/"
	err := os.MkdirAll(dir, 0777)
	return dir, err
}

package tracer

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
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
	scamperDaemonRunning = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "traces_scamper_daemon_running",
			Help: "Whether the scamper daemon is running or not.",
		},
	)

	// hostname of the current machine. Only call os.Hostname once, because the
	// result should never change.
	//lint:ignore U1000 hostname is used for testing.
	hostname string

	// log.Fatal turned into a variable to aid in testing of error conditions.
	logFatal = log.Fatal
)

func init() {
	var err error
	hostname, err = os.Hostname()
	rtx.Must(err, "Could not call os.Hostname")
}

// Metadata is the first line of the traceroute .jsonl file.
//
// TODO: move this struct to ETL parser.
type Metadata struct {
	UUID                    string
	TracerouteCallerVersion string
	CachedResult            bool
	CachedUUID              string
}

// extractUUID retrieves the UUID from a cached line.
//
// TODO: Eliminate the need to unmarshal data we marshaled in the first place.
//lint:ignore U1000 extractUUID is used for testing.
func extractUUID(metaline string) string {
	var metaResult Metadata
	err := json.Unmarshal([]byte(metaline), &metaResult)
	if err != nil {
		log.Println("Could not parse cached results:", metaline)
		return ""
	}
	return metaResult.UUID
}

// GetMetaline returns the what the first line of the output jsonl file should
// be. Parameter isCache indicates whether this meta line is for an original
// trace test or a cached test, and parameter cachedUUID is the original test if
// isCache is 1.
func GetMetaline(conn connection.Connection, isCache bool, cachedUUID string) string {
	// Write the UUID as the first line of the file. If we want to add other
	// metadata, this is the place to do it.
	//
	// TODO: decide what other metadata to add to the traceroute output. If we
	// decide to add more, then this quick-and-dirty approach should be converted
	// into proper json.Marshal calls.
	uuid, err := conn.UUID()
	rtx.PanicOnError(err, "Could not parse UUID - this should never happen")

	meta := Metadata{
		UUID:                    uuid,
		TracerouteCallerVersion: prometheusx.GitShortCommit,
		CachedResult:            isCache,
		CachedUUID:              cachedUUID,
	}

	metaJSON, _ := json.Marshal(meta)

	return string(metaJSON) + "\n"
}

// createTimePath returns a string with date in format prefix/yyyy/mm/dd/ after
// creating a directory of the same name.
func createTimePath(outputPath string, t time.Time) (string, error) {
	dir := outputPath + "/" + t.Format("2006/01/02") + "/"
	err := os.MkdirAll(dir, 0777)
	return dir, err
}

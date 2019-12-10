package tracer

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/connection"
	"github.com/m-lab/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	tracesInProgress = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "traces_in_progress",
			Help: "The number of traces currently being run",
		})
	crashedTraces = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "traces_crashed_total",
			Help: "The number of traces that have crashed",
		})
	tracesNotPerformed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "traces_skipped_total",
			Help: "The number of traces that have not been performed because there was an error cached",
		})

	// hostname of the current machine. Only call os.Hostname once, because the
	// result should never change.
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

// createTimePath returns a string with date in format
// prefix/yyyy/mm/dd/hostname/ after creating a directory of the same name.
func createTimePath(outputPath string, t time.Time) string {
	dir := outputPath + "/" + t.Format("2006/01/02") + "/"
	rtx.PanicOnError(os.MkdirAll(dir, 0777), "Could not create the output dir")
	return dir
}

// generatesFilename creates the string filename for storing the data.
func generateFilename(cookie string, t time.Time) string {
	c, err := strconv.ParseInt(cookie, 16, 64)
	rtx.PanicOnError(err, "Could not turn cookie into number")
	return t.Format("20060102T150405Z") + "_" + uuid.FromCookie(uint64(c)) + ".jsonl"
}

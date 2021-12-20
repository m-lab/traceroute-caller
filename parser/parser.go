// Package parser handles parsing of scamper output in JSONL format.
package parser

import (
	"errors"
	"fmt"
	"time"
)

var (
	errTracerouteType = errors.New("unknown traceroute type")
	errTracerouteFile = errors.New("invalid traceroute file")
	errMetadata       = errors.New("invalid metadata")
	errMetadataUUID   = errors.New("invalid UUID (empty)")
	errCycleStart     = errors.New("invalid cycle-start")
	errCycleStartType = errors.New("invalid cycle-start type")
	errTraceType      = errors.New("invalid trace type")
	errTracelbLine    = errors.New("invalid tracelb line")
	errCycleStop      = errors.New("invalid cycle-stop")
	errCycleStopType  = errors.New("invalid cycle-stop type")
)

// TS contains a unix epoch timestamp.
type TS struct {
	Sec  int64 `json:"sec"`
	Usec int64 `json:"usec"`
}

// CyclestartLine contains the information about the scamper "cyclestart".
type CyclestartLine struct {
	Type      string  `json:"type" bigquery:"type"`
	ListName  string  `json:"list_name" bigquery:"list_name"`
	ID        float64 `json:"id" bigquery:"id"`
	Hostname  string  `json:"hostname" bigquery:"hostname"`
	StartTime float64 `json:"start_time" bigquery:"start_time"`
}

// CyclestopLine contains the ending details from the scamper tool.
// ListName, ID, and Hostname seem to match CyclestartLine.
type CyclestopLine struct {
	Type     string  `json:"type" bigquery:"type"`
	ListName string  `json:"list_name" bigquery:"list_name"`
	ID       float64 `json:"id" bigquery:"id"`
	Hostname string  `json:"hostname" bigquery:"hostname"`
	StopTime float64 `json:"stop_time" bigquery:"stop_time"`
}

// ParsedData defines the interface for parsed traceroute data.
type ParsedData interface {
	StartTime() time.Time
	ExtractHops() []string
}

// TracerouteParser defines the interface for raw traceroute data.
type TracerouteParser interface {
	ParseRawData(rawData []byte) (ParsedData, error)
}

// New returns a new traceroute parser correspondong to the traceroute type.
func New(traceType string) (TracerouteParser, error) {
	switch traceType {
	case "mda":
		return &scamper1Parser{}, nil
	}
	return nil, fmt.Errorf("%q: %v", traceType, errTracerouteType)
}

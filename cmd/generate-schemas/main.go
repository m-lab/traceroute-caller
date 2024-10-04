package main

import (
	"flag"
	"os"

	"github.com/m-lab/go/cloud/bqx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/traceroute-caller/hopannotation"
	"github.com/m-lab/traceroute-caller/parser"

	"cloud.google.com/go/bigquery"
)

var (
	scamper2schema string
	hop1schema     string
)

func init() {
	flag.StringVar(&scamper2schema, "scamper2", "/var/spool/datatypes/scamper2.json", "filename to write scamper2 schema")
	flag.StringVar(&hop1schema, "hopannotation1", "/var/spool/datatypes/hopannotation1.json", "filename to write hopannotation1 schema")
}

func main() {
	flag.Parse()
	// TODO(soltesz): parser.Schema1 does not natively support BigQuery schema inference.

	// Generate and save hopannotation1 schema for autoloading.
	hop1 := hopannotation.HopAnnotation1{}
	sch, err := bigquery.InferSchema(hop1)
	rtx.Must(err, "failed to generate scamper2 schema")
	sch = bqx.RemoveRequired(sch)
	b, err := sch.ToJSONFields()
	rtx.Must(err, "failed to marshal schema")
	os.WriteFile(hop1schema, b, 0o644)

	// Generate and save scamper2 schema for autoloading.
	row2 := parser.Scamper2{}
	sch, err = bigquery.InferSchema(row2)
	rtx.Must(err, "failed to generate scamper2 schema")
	sch = bqx.RemoveRequired(sch)
	b, err = sch.ToJSONFields()
	rtx.Must(err, "failed to marshal schema")
	os.WriteFile(scamper2schema, b, 0o644)
}

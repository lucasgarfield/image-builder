package sbom

import (
	"encoding/json"
	"fmt"

	pb "github.com/protobom/protobom/pkg/sbom"
)

type StandardType uint64

const (
	StandardTypeNone StandardType = iota
	StandardTypeSpdx
)

func (t StandardType) String() string {
	switch t {
	case StandardTypeNone:
		return "none"
	case StandardTypeSpdx:
		return "spdx"
	default:
		panic("invalid standard type")
	}
}

func (t StandardType) MarshalJSON() ([]byte, error) {
	var s string

	if t == StandardTypeNone {
		s = ""
	} else {
		s = t.String()
	}

	return json.Marshal(s)
}

func (t *StandardType) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case `""`:
		*t = StandardTypeNone
	case `"spdx"`:
		*t = StandardTypeSpdx
	default:
		return fmt.Errorf("invalid SBOM standard type: %s", data)
	}
	return nil
}

type Document struct {
	// doc is populated by Generate. The depsolver still returns the legacy JSON fields below.
	doc *pb.Document

	// type of the document standard
	DocType StandardType

	// document in a specific standard JSON raw format
	Document json.RawMessage
}

func NewDocument(docType StandardType, doc json.RawMessage) (*Document, error) {
	switch docType {
	case StandardTypeSpdx:
		docType = StandardTypeSpdx
	default:
		return nil, fmt.Errorf("unsupported SBOM document type: %s", docType)
	}

	return &Document{
		DocType:  docType,
		Document: doc,
	}, nil
}

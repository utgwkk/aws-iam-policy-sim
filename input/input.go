package input

import (
	"errors"
)

type Input struct {
	Statement []Statement
}

type Statement struct {
	Action StringOrStringList

	Resource StringOrStringList
}

type NormalizedStatement struct {
	Actions []string

	Resources []string
}

func (s *Statement) Normalize() (*NormalizedStatement, error) {
	if len(s.Action) == 0 {
		return nil, errors.New("action must not be empty")
	}
	if len(s.Resource) == 0 {
		return nil, errors.New("resource must not be empty")
	}

	return &NormalizedStatement{
		Actions:   []string(s.Action),
		Resources: []string(s.Resource),
	}, nil
}

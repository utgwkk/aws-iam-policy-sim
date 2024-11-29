package input

import (
	"errors"
)

type Input struct {
	Simulates []Simulate `json:"simulates"`
}

type Simulate struct {
	Action StringOrStringList `json:"action"`

	Resource StringOrStringList `json:"resource"`
}

type NormalizedSimulate struct {
	Actions []string

	Resources []string
}

func (s *Simulate) Normalize() (*NormalizedSimulate, error) {
	if len(s.Action) == 0 {
		return nil, errors.New("action must not be empty")
	}
	if len(s.Resource) == 0 {
		return nil, errors.New("resource must not be empty")
	}

	return &NormalizedSimulate{
		Actions:   []string(s.Action),
		Resources: []string(s.Resource),
	}, nil
}

package domain

import "sort"

type Registry struct {
	guardrails map[string]Guardrail
}

func NewRegistry(items ...Guardrail) Registry {
	guardrails := make(map[string]Guardrail, len(items))
	for _, item := range items {
		guardrails[item.Name()] = item
	}
	return Registry{guardrails: guardrails}
}

func (r Registry) Get(name string) (Guardrail, bool) {
	item, ok := r.guardrails[name]
	return item, ok
}

func (r Registry) Names() []string {
	names := make([]string, 0, len(r.guardrails))
	for name := range r.guardrails {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

package provider

import (
	"sort"

	"github.com/cmouse/dbus-passkey/internal/types"
)

// ScoredProvider pairs a Provider with its registry priority.
type ScoredProvider struct {
	Provider Provider
	Priority int
}

// SelectCandidates filters and ranks providers for a MakeCredential operation.
// Hardware providers arrive pre-filtered by the fido2 layer.
func SelectCandidates(
	providers []ScoredProvider,
	opts *types.MakeCredentialOptions,
) []ScoredProvider {
	var out []ScoredProvider
	for _, sp := range providers {
		p := sp.Provider
		if opts.AuthenticatorAttachment != "" {
			if opts.AuthenticatorAttachment == "platform" && p.Type() != "software" {
				continue
			}
			if opts.AuthenticatorAttachment == "cross-platform" && p.Type() != "hardware" {
				continue
			}
		}
		if len(opts.PubKeyCredParams) > 0 && !supportsAnyAlg(p, opts.PubKeyCredParams) {
			continue
		}
		out = append(out, sp)
	}
	sortByPriority(out)
	return out
}

// SelectAssertionCandidates filters providers for GetAssertion.
func SelectAssertionCandidates(
	providers []ScoredProvider,
	opts *types.GetAssertionOptions,
	hasCredsMap map[string][][]byte,
) []ScoredProvider {
	var out []ScoredProvider
	for _, sp := range providers {
		p := sp.Provider
		if p.Type() == "software" {
			ids, ok := hasCredsMap[p.ID()]
			if !ok || len(ids) == 0 {
				continue
			}
		}
		out = append(out, sp)
	}
	sortByPriority(out)
	return out
}

func supportsAnyAlg(p Provider, params []types.CredentialParam) bool {
	supported := p.SupportedAlgorithms()
	for _, param := range params {
		for _, alg := range supported {
			if alg == param.Alg {
				return true
			}
		}
	}
	return false
}

func sortByPriority(providers []ScoredProvider) {
	sort.SliceStable(providers, func(i, j int) bool {
		return providers[i].Priority > providers[j].Priority
	})
}

// ProvidersToDBusCandidates converts ScoredProviders to D-Bus candidate maps.
func ProvidersToDBusCandidates(providers []ScoredProvider, credIDs map[string][]byte) []map[string]interface{} {
	out := make([]map[string]interface{}, len(providers))
	for i, sp := range providers {
		p := sp.Provider
		cid, _ := credIDs[p.ID()]
		out[i] = map[string]interface{}{
			"provider_id":       p.ID(),
			"provider_name":     p.Name(),
			"provider_type":     p.Type(),
			"transports":        p.Transports(),
			"credential_id":     cid,
			"user_name":         "",
			"user_display_name": "",
		}
	}
	return out
}

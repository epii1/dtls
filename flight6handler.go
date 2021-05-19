package dtls

import (
	"context"

	"github.com/pion/dtls/v2/pkg/crypto/prf"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/alert"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

func flight6Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert.Alert, error) {
	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence-1,
		handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, true, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok = msgs[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	// Other party retransmitted the last flight.
	return flight6, nil, nil
}

func flight6Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert.Alert, error) {
	if len(state.SessionID) > 0 && !state.cipherSuite.IsInitialized() {
		serverRandom := state.localRandom.MarshalFixed()
		clientRandom := state.remoteRandom.MarshalFixed()

		if err := state.cipherSuite.Init(state.masterSecret, clientRandom[:], serverRandom[:], false); err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.masterSecret)
	}

	var pkts []*packet

	var serverHello *handshake.Handshake
	if len(state.SessionID) > 0 {
		cipherSuiteID := uint16(state.cipherSuite.ID())
		serverHello = &handshake.Handshake{
			Message: &handshake.MessageServerHello{
				Version:           protocol.Version1_2,
				Random:            state.localRandom,
				SessionID:         state.SessionID,
				CipherSuiteID:     &cipherSuiteID,
				CompressionMethod: defaultCompressionMethods()[0],
			},
		}
		pkts = append(pkts, &packet{
			record: &recordlayer.RecordLayer {
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: serverHello,
			},
		})
	}

	pkts = append(pkts,
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &protocol.ChangeCipherSpec{},
			},
		})

	if len(state.localVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeClientKeyExchange, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeCertificateVerify, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, true, false},
		)
		if len(state.SessionID) > 0 {
			plainText = cache.pullAndMerge(
				handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
			)
			b, _:= serverHello.Marshal()
			plainText = append(plainText, b...)
		}

		var err error
		state.localVerifyData, err = prf.VerifyDataServer(state.masterSecret, plainText, state.cipherSuite.HashFunc())
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
					Epoch:   1,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageFinished{
						VerifyData: state.localVerifyData,
					},
				},
			},
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		},
	)
	return pkts, nil, nil
}

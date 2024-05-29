package model

import (
	"github.com/bytemare/crypto"
)

// Round1Data is the output data of the Init() function, to be broadcast to all participants.
type Round1Data struct {
	ProofOfKnowledge Signature
	SenderIdentifier *crypto.Scalar
	Commitment       []*crypto.Element
}

// Bytes encode the round 1 data and return it as byte array
func (d Round1Data) Bytes() []byte {
	commitment := []byte{}
	for _, commit := range d.Commitment {
		commitment = append(commitment, commit.Encode()...)
	}

	out := []byte{}
	out = append(out, d.SenderIdentifier.Encode()...)
	out = append(out, d.ProofOfKnowledge.Encode()...)
	out = append(out, commitment...)

	return out
}

func (d Round1Data) IsEqual(other *Round1Data) bool {
	if d.ProofOfKnowledge.Z.Equal(other.ProofOfKnowledge.Z) != 1 {
		return false
	}

	if d.ProofOfKnowledge.R.Equal(other.ProofOfKnowledge.R) != 1 {
		return false
	}

	if d.SenderIdentifier.Equal(other.SenderIdentifier) != 1 {
		return false
	}

	if len(d.Commitment) != len(other.Commitment) {
		return false
	}

	for i, c := range d.Commitment {
		if c.Equal(other.Commitment[i]) != 1 {
			return false
		}
	}

	return true

}

func NewRound1DataFromBytes(cg crypto.Group, data []byte) (*Round1Data, error) {
	senderBytes := data[:cg.ScalarLength()]
	proofBytes := data[cg.ScalarLength() : cg.ScalarLength()+64]
	commitmentsBytes := data[cg.ScalarLength()+64:]

	r1Data := &Round1Data{
		ProofOfKnowledge: Signature{
			R: cg.NewElement(),
			Z: cg.NewScalar(),
		},
		SenderIdentifier: cg.NewScalar(),
		Commitment:       []*crypto.Element{},
	}

	for i := 0; i < len(commitmentsBytes); i += cg.ElementLength() {
		commitment := cg.NewElement()
		err := commitment.Decode(commitmentsBytes[i : i+cg.ElementLength()])
		if err != nil {
			//utils.Logger.With("err", err).Error("cant decode commitment")
			return nil, err
		}

		r1Data.Commitment = append(r1Data.Commitment, commitment)
	}

	err := r1Data.ProofOfKnowledge.Decode(cg, proofBytes)
	if err != nil {
		//utils.Logger.With("err", err).Error("cant decode proof_of_knowledge")
		return nil, err
	}

	err = r1Data.SenderIdentifier.Decode(senderBytes)
	if err != nil {
		//utils.Logger.With("err", err).Error("cant decode identifier")
		return nil, err
	}

	return r1Data, nil
}

package model

import group "github.com/bytemare/crypto"

// Round2Data is an output of the Continue() function, to be sent to the Receiver.
type Round2Data struct {
	SenderIdentifier *group.Scalar

	ReceiverIdentifier *group.Scalar
	SecretShare        *group.Scalar
}

func (d Round2Data) Bytes() []byte {
	out := []byte{}
	out = append(out, d.SenderIdentifier.Encode()...)
	out = append(out, d.ReceiverIdentifier.Encode()...)
	out = append(out, d.SecretShare.Encode()...)

	return out
}

func (d Round2Data) IsEqual(other *Round2Data) bool {
	if d.SenderIdentifier.Equal(other.SenderIdentifier) != 1 {
		return false
	}

	if d.ReceiverIdentifier.Equal(other.ReceiverIdentifier) != 1 {
		return false
	}

	if d.SecretShare.Equal(other.SecretShare) != 1 {
		return false
	}

	return true
}

func NewRound2DataFromBytes(cg group.Group, data []byte) (*Round2Data, error) {
	r2Data := &Round2Data{
		SenderIdentifier:   cg.NewScalar(),
		ReceiverIdentifier: cg.NewScalar(),
		SecretShare:        cg.NewScalar(),
	}

	err := r2Data.SenderIdentifier.Decode(data[:cg.ScalarLength()])
	if err != nil {
		return nil, err
	}

	err = r2Data.ReceiverIdentifier.Decode(data[cg.ScalarLength() : cg.ScalarLength()*2])
	if err != nil {
		return nil, err
	}

	err = r2Data.SecretShare.Decode(data[cg.ScalarLength()*2:])
	if err != nil {
		return nil, err
	}

	return r2Data, nil
}

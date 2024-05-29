package frost

import (
	"github.com/bytemare/frost/dkg"
	"github.com/bytemare/frost/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCommitment_EncodeRistretto255(t *testing.T) {
	configuration := Ristretto255.Configuration()
	FirstID := configuration.IDFromInt(1)
	SecondID := configuration.IDFromInt(2)

	participantOne := dkg.NewParticipant(
		configuration.Ciphersuite,
		FirstID,
		2,
		2,
	)

	participantTwo := dkg.NewParticipant(
		configuration.Ciphersuite,
		SecondID,
		2,
		2,
	)

	r1DataOne := participantOne.Init()
	r1DataTwo := participantTwo.Init()

	r1DataBytes := r1DataOne.Bytes()
	decodedR1Data, err := model.NewRound1DataFromBytes(configuration.Ciphersuite.Group, r1DataBytes)
	assert.NoError(t, err)
	assert.True(t, r1DataOne.IsEqual(decodedR1Data))

	_, err = participantOne.Continue([]*model.Round1Data{r1DataOne, r1DataTwo})
	assert.NoError(t, err)

	r2DataTwo, err := participantTwo.Continue([]*model.Round1Data{r1DataOne, r1DataTwo})
	assert.NoError(t, err)

	r2DataBytes := r2DataTwo[0].Bytes()
	decodedR2Data, err := model.NewRound2DataFromBytes(configuration.Ciphersuite.Group, r2DataBytes)
	assert.NoError(t, err)
	assert.True(t, r2DataTwo[0].IsEqual(decodedR2Data))

	participantsSecretKey, _, groupPublicKeyGeneratedInDKG, err := participantOne.Finalize(
		[]*model.Round1Data{r1DataOne, r1DataTwo},
		r2DataTwo,
	)

	configuration.GroupPublicKey = groupPublicKeyGeneratedInDKG

	finalParticipant := configuration.Participant(FirstID, participantsSecretKey)

	commitment := finalParticipant.Commit()
	commitmentByte := commitment.Bytes()
	decodedCommitment, err := NewCommitmentFromBytes(Ristretto255, commitmentByte)
	assert.NoError(t, err)
	assert.True(t, commitment.IsEqual(decodedCommitment))

}

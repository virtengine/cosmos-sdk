package keeper_test

import (
	"errors"
	"fmt"
	"strings"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/gov/types"
)

func (suite *KeeperTestSuite) TestGetSetProposal() {
	tp := TestProposal
	proposal, err := suite.app.GovKeeper.SubmitProposal(suite.ctx, tp, []sdk.Msg{})
	suite.Require().NoError(err)
	proposalID := proposal.ProposalId
	suite.app.GovKeeper.SetProposal(suite.ctx, proposal)

	gotProposal, ok := suite.app.GovKeeper.GetProposal(suite.ctx, proposalID)
	suite.Require().True(ok)
	suite.Require().True(proposal.Equal(gotProposal))
}

func (suite *KeeperTestSuite) TestActivateVotingPeriod() {
	tp := TestProposal
	proposal, err := suite.app.GovKeeper.SubmitProposal(suite.ctx, tp, []sdk.Msg{})
	suite.Require().NoError(err)

	suite.Require().True(proposal.VotingStartTime.Equal(time.Time{}))

	suite.app.GovKeeper.ActivateVotingPeriod(suite.ctx, proposal)

	suite.Require().True(proposal.VotingStartTime.Equal(suite.ctx.BlockHeader().Time))

	proposal, ok := suite.app.GovKeeper.GetProposal(suite.ctx, proposal.ProposalId)
	suite.Require().True(ok)

	activeIterator := suite.app.GovKeeper.ActiveProposalQueueIterator(suite.ctx, proposal.VotingEndTime)
	suite.Require().True(activeIterator.Valid())

	proposalID := types.GetProposalIDFromBytes(activeIterator.Value())
	suite.Require().Equal(proposalID, proposal.ProposalId)
	activeIterator.Close()
}

var _ sdk.Msg = &testProposalMsg{}

type testProposalMsg struct {
	signer string
}

func newTestProposalMsg(signer string) *testProposalMsg {
	return &testProposalMsg{signer: signer}
}

func (msg *testProposalMsg) ValidateBasic() error { return nil }

func (msg *testProposalMsg) GetSigners() []string {
	return []string{msg.signer}
}

func (msg *testProposalMsg) String() string { return "testProposalMsg" }

func (msg *testProposalMsg) Reset() {}

func (msg *testProposalMsg) ProtoMessage() {}

func (msg *testProposalMsg) Route() string {
	return "invalidroute"
}

func (suite *KeeperTestSuite) TestSubmitProposal() {
	govAccount := suite.app.GovKeeper.GetGovernanceAccount(suite.ctx)
	// Proposal is for the gov module to vote on another proposal :)
	voteProposal := []sdk.Msg{types.NewMsgVote(govAccount.GetAddress(), 0, types.OptionYes)}
	invalidAddressProposal := []sdk.Msg{newTestProposalMsg("invalidAddrs")}
	invalidRouteProposal := []sdk.Msg{newTestProposalMsg(govAccount.GetAddress().String())}

	testCases := []struct {
		content     types.Content
		messages    []sdk.Msg
		expectedErr error
	}{
		{&types.TextProposal{Title: "title", Description: "description"}, voteProposal, nil},
		// Keeper does not check the validity of title and description, no error
		{&types.TextProposal{Title: "", Description: "description"}, voteProposal, nil},
		{&types.TextProposal{Title: strings.Repeat("1234567890", 100), Description: "description"}, voteProposal, nil},
		{&types.TextProposal{Title: "title", Description: ""}, voteProposal, nil},
		{&types.TextProposal{Title: "title", Description: strings.Repeat("1234567890", 1000)}, voteProposal, nil},
		// TODO: add errors for empty messages and messages with invalid routes
		{&types.TextProposal{Title: "title", Description: "description"}, invalidAddressProposal, types.ErrInvalidSigner},
		{&types.TextProposal{Title: "title", Description: "description"}, invalidRouteProposal, types.ErrUnroutableProposalMsg},
	}

	for i, tc := range testCases {
		_, err := suite.app.GovKeeper.SubmitProposal(suite.ctx, tc.content, tc.messages)
		suite.Require().True(errors.Is(tc.expectedErr, err), "tc #%d; got: %v, expected: %v", i, err, tc.expectedErr)
	}
}

func (suite *KeeperTestSuite) TestGetProposalsFiltered() {
	proposalID := uint64(1)
	status := []types.ProposalStatus{types.StatusDepositPeriod, types.StatusVotingPeriod}

	addr1 := sdk.AccAddress("foo_________________")

	for _, s := range status {
		for i := 0; i < 50; i++ {
			p, err := types.NewProposal(TestProposal, []sdk.Msg{}, proposalID, time.Now(), time.Now())
			suite.Require().NoError(err)

			p.Status = s

			if i%2 == 0 {
				d := types.NewDeposit(proposalID, addr1, nil)
				v := types.NewVote(proposalID, addr1, types.NewNonSplitVoteOption(types.OptionYes))
				suite.app.GovKeeper.SetDeposit(suite.ctx, d)
				suite.app.GovKeeper.SetVote(suite.ctx, v)
			}

			suite.app.GovKeeper.SetProposal(suite.ctx, p)
			proposalID++
		}
	}

	testCases := []struct {
		params             types.QueryProposalsParams
		expectedNumResults int
	}{
		{types.NewQueryProposalsParams(1, 50, types.StatusNil, nil, nil), 50},
		{types.NewQueryProposalsParams(1, 50, types.StatusDepositPeriod, nil, nil), 50},
		{types.NewQueryProposalsParams(1, 50, types.StatusVotingPeriod, nil, nil), 50},
		{types.NewQueryProposalsParams(1, 25, types.StatusNil, nil, nil), 25},
		{types.NewQueryProposalsParams(2, 25, types.StatusNil, nil, nil), 25},
		{types.NewQueryProposalsParams(1, 50, types.StatusRejected, nil, nil), 0},
		{types.NewQueryProposalsParams(1, 50, types.StatusNil, addr1, nil), 50},
		{types.NewQueryProposalsParams(1, 50, types.StatusNil, nil, addr1), 50},
		{types.NewQueryProposalsParams(1, 50, types.StatusNil, addr1, addr1), 50},
		{types.NewQueryProposalsParams(1, 50, types.StatusDepositPeriod, addr1, addr1), 25},
		{types.NewQueryProposalsParams(1, 50, types.StatusDepositPeriod, nil, nil), 50},
		{types.NewQueryProposalsParams(1, 50, types.StatusVotingPeriod, nil, nil), 50},
	}

	for i, tc := range testCases {
		suite.Run(fmt.Sprintf("Test Case %d", i), func() {
			proposals := suite.app.GovKeeper.GetProposalsFiltered(suite.ctx, tc.params)
			suite.Require().Len(proposals, tc.expectedNumResults)

			for _, p := range proposals {
				if types.ValidProposalStatus(tc.params.ProposalStatus) {
					suite.Require().Equal(tc.params.ProposalStatus, p.Status)
				}
			}
		})
	}
}

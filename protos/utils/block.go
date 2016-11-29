/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/peer"
)

// UnmarshallBlock converts a byte array generated by Bytes() back to a block.
func UnmarshallBlock(blockBytes []byte) (*peer.Block2, error) {
	block := &peer.Block2{}
	err := proto.Unmarshal(blockBytes, block)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal block: %s", err)
	}
	return block, nil
}

// GetTransactions gets Transactions out of Block2
func GetTransactions(block *peer.Block2) ([]*peer.Transaction, error) {
	txs := []*peer.Transaction{}
	for _, b := range block.Transactions {
		tx := &peer.Transaction{}
		err := proto.Unmarshal(b, tx)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal transaction: %s", err)
		}
	}
	return txs, nil
}
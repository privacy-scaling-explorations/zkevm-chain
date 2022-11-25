// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

contract InstanceVerifier {
  // TODO:
  // - docs
  // - verify special 'block hash import' transactions
  // - verify history hashes
  function _buildTable (
    uint256 MAX_TXS,
    uint256 MAX_CALLDATA,
    uint256 chainId,
    uint256 parentStateRoot,
    bytes calldata witness,
    bool clearMemory
  ) internal pure returns (uint256[] memory table, uint256 blockHash) {
    // https://github.com/privacy-scaling-explorations/zkevm-specs/blob/08c6c30a7b53f83558a7ea7e50dc0e4d74fab0c8/src/zkevm_specs/public_inputs.py#L290
    assembly ("memory-safe") {
      //@INCLUDE:rlp.yul
      //@INCLUDE:utils.yul

      // Layout of public input row
      // 00..32: q_block_table: FQ  # Fixed Column
      // 32..64: block_table: BlockTableRow
      // 64..96: q_tx_table: FQ  # Fixed Column
      // 96..224: tx_table: TxTableRow
      // 224..256: raw_public_inputs: FQ
      // 256..288: rpi_rlc_acc: FQ  # raw_public_inputs accumulated RLC from bottom to top
      // 288..320: rand_rpi: FQ
      // 320..352: q_end: FQ  # Fixed Column
      // 352..384: q_not_end: FQ  # Fixed Column

      // Writes to the public input table and
      // the raw_public_inputs array.
      function appendBlockRow (value) {
        value := mod(value, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
        let callframe := mload(96)
        // callframe.tableOffset
        let ptr := mload(callframe)

        // q_block_table
        mstore(ptr, 1)
        ptr := add(ptr, 32)

        // block_table
        mstore(ptr, value)
        ptr := add(ptr, 32)

        {
          // increment index
          let rpi_ptr := mload(0)
          mstore(0, add(rpi_ptr, 32))

          // store block value into raw_public_inputs
          mstore(rpi_ptr, value)
        }

        // skip:
        // q_tx_table
        // tx_table
        // raw_public_inputs
        // rpi_rlc_acc
        // rand_rpi
        // q_end
        // q_not_end
        ptr := add(ptr, 320)
        mstore(callframe, ptr)
      }

      // Only updates the `raw_public_inputs` array.
      function appendExtraRow (value) {
        value := mod(value, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)

        // increment index
        let rpi_ptr := mload(0)
        mstore(0, add(rpi_ptr, 32))

        // store block value into raw_public_inputs
        mstore(rpi_ptr, value)
      }

      // Writes to the public input table and
      // the raw_public_inputs array.
      function appendTxRow (txId, tag, value) {
        value := mod(value, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
        let callframe := mload(96)
        // callframe.tableOffset
        let ptr := mload(callframe)

        // q_block_table
        // block_table
        ptr := add(ptr, 64)

        // q_tx_table
        mstore(ptr, 1)
        ptr := add(ptr, 32)

        // tx_table
        mstore(ptr, txId)
        ptr := add(ptr, 32)

        // tx.tag
        mstore(ptr, tag)
        ptr := add(ptr, 32)

        // tx.index
        ptr := add(ptr, 32)

        // tx.value
        mstore(ptr, value)
        ptr := add(ptr, 32)

        // update `raw_public_inputs` array
        {
          // increment index
          let rpi_ptr := mload(0)
          mstore(0, add(rpi_ptr, 32))

          // tx_id_col
          mstore(rpi_ptr, txId)

          let id_index_value_spread := mload(add(callframe, 96))

          // skip index_col
          rpi_ptr := add(rpi_ptr, id_index_value_spread)

          // value_col
          rpi_ptr := add(rpi_ptr, id_index_value_spread)
          mstore(rpi_ptr, value)
        }

        // skip:
        // raw_public_inputs
        // rpi_rlc_acc
        // rand_rpi
        // q_end
        // q_not_end
        ptr := add(ptr, 160)

        mstore(callframe, ptr)
      }

      function appendCallDataRow (txId, index, value) {
        value := mod(value, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
        let callframe := mload(96)
        // advance public input row
        {
          // callframe.calldataTableOffset
          let ptr := mload(add(callframe, 32))

          // skip:
          // q_block_table
          // block_table
          // q_tx_table
          ptr := add(ptr, 96)

          // tx_table
          mstore(ptr, txId)
          ptr := add(ptr, 32)

          // skip: tx.tag
          ptr := add(ptr, 32)

          // tx.index
          mstore(ptr, index)
          ptr := add(ptr, 32)

          // tx.value
          mstore(ptr, value)
          ptr := add(ptr, 32)

          // skip:
          // raw_public_inputs
          // rpi_rlc_acc
          // rand_rpi
          // q_end
          // q_not_end
          ptr := add(ptr, 160)

          // callframe.calldataTableOffset
          mstore(add(callframe, 32), ptr)
        }

        // advance raw_public_inputs
        {
          // callframe.rpi_ptr_call_data
          let ptr := add(callframe, 64)

          // increment index
          let rpi_ptr := mload(ptr)
          mstore(ptr, add(rpi_ptr, 32))

          // tx_id_col
          mstore(rpi_ptr, txId)

          let id_index_value_spread := mload(add(callframe, 96))
          // index_col
          rpi_ptr := add(rpi_ptr, id_index_value_spread)
          mstore(rpi_ptr, index)

          // value_col
          rpi_ptr := add(rpi_ptr, id_index_value_spread)
          mstore(rpi_ptr, value)
        }
      }

      // main
      // 0  = rpi_ptr
      // 32 = start of raw_public_inputs ptr
      // 64 = free memory ptr
      // 96 = callframe ptr
      table := mload(64)
      mstore(96, table)
      // reserve 128 bytes for callframe
      // 0..32: callframe.tableOffset
      // 32..64: callframe.calldataTableOffset
      // 64..96: callframe.rpi_ptr_call_data
      // 96..128: callframe.id_index_value_spread
      // 128..160: callframe.calldataBytes
      table := add(table, 160)
      {
        // hashes(256) + block(8) + extra(3)
        let BLOCK_FIELDS := 267
        let TX_FIELDS := 10
        let MAX_TX_FIELDS := mul(TX_FIELDS, MAX_TXS)
        let N_FIELDS := add(MAX_TX_FIELDS, MAX_CALLDATA)
        // initial zero row
        N_FIELDS := add(1, N_FIELDS)
        let N_RAW_INPUTS := add(BLOCK_FIELDS, mul(3, N_FIELDS))
        let PI_ROW_FIELDS := 12
        let N_PI_ROWS := mul(N_RAW_INPUTS, PI_ROW_FIELDS)
        // uint256[].length
        mstore(table, N_PI_ROWS)
        table := add(table, 32)

        // end of pi table
        let endOfRows := add(table, mul(N_PI_ROWS, 32))

        // start of raw_public_inputs
        mstore(32, endOfRows)
        // rpi_ptr
        mstore(0, endOfRows)

        // end of raw_public_inputs, update free memory pointer
        {
          let len := mul(N_RAW_INPUTS, 32)
          let memTail := add(endOfRows, len)
          mstore(64, memTail)
          // XXX: normally we could check if the memory region
          // is dirty via MSIZE, though solc complaints.
          // Make it optional.
          if clearMemory {
            calldatacopy(table, calldatasize(), len)
          }
        }

        // callframe.tableOffset
        let callframe := mload(96)
        mstore(callframe, table)

        // callframe.calldataTableOffset
        let calldataTable := add(table, mul(384, MAX_TX_FIELDS))
        mstore(add(callframe, 32), calldataTable)

        // callframe.rpi_ptr_call_data
        mstore(add(callframe, 64), add(endOfRows, mul(add(BLOCK_FIELDS, MAX_TX_FIELDS), 32)))

        // callframe.id_index_value_spread
        mstore(
          add(callframe, 96),
          mul(
            32,
            add(1, add(mul(TX_FIELDS, MAX_TXS), MAX_CALLDATA))
          )
        )

        // MAX_CALLDATA padding
        {
          let head := calldataTable
          let tail := add(head, mul(add(MAX_CALLDATA, 1), 384))
          head := add(head, 64)

          for {} lt(head, tail) {} {
            // q_tx_table
            mstore(head, 1)
            // tx_table.tag
            mstore(add(head, 64), /*CONST_TX_TAG_CALL_DATA*/ 11)
            head := add(head, 384)
          }
        }
      }

      // calldata offsets
      let dataOffset := witness.offset
      let dataOffsetTail := add(dataOffset, witness.length)

      // block+extra table
      {
        let ptr, values, nItems, hash := decodeFlat(dataOffset)
        require(eq(nItems, 15), "BLOCK_ITEMS")

        // initial zero
        appendBlockRow(0)
        // coinbase
        appendBlockRow(loadValue(values, 2))
        // gas_limit
        appendBlockRow(loadValue(values, 9))
        // number
        appendBlockRow(loadValue(values, 8))
        // time
        appendBlockRow(loadValue(values, 11))
        // difficulty
        appendBlockRow(loadValue(values, 7))
        // base fee
        appendBlockRow(0)
        // chain id
        appendBlockRow(chainId)

        // history hashes
        {
          let tail := add(ptr, 8192)
          for {} lt(ptr, tail) { ptr := add(ptr, 32) } {
            appendBlockRow(calldataload(ptr))
          }
        }

        // extra fields
        // block hash
        appendExtraRow(hash)
        // stateRoot
        appendExtraRow(loadValue(values, 3))
        // parent stateRoot
        appendExtraRow(parentStateRoot)

        dataOffset := ptr
        require(or(eq(dataOffset, dataOffsetTail), lt(dataOffset, dataOffsetTail)), "DATA")
        blockHash := hash
      }
      // end of block+extra table

      // rewind `callframe.tableOffset`
      mstore(mload(96), table)

      // tx table
      {
        // initial zero row
        appendTxRow(0, 0, 0)
        appendCallDataRow(0, 0, 0)

        let txId := 0
        for {} lt(dataOffset, dataOffsetTail) {} {
          txId := add(txId, 1)

          let ptr, values, nItems, hash := decodeFlat(dataOffset)
          require(eq(nItems, 9), "TX_ITEMS")
          dataOffset := ptr
          let txFrom := calldataload(dataOffset)
          // from, r,s
          dataOffset := add(dataOffset, 96)

          {
            let _chain_id := loadValue(values, 6)
            require(eq(_chain_id, chainId), "TX_CHAINID")
          }

          {
            let txNonce := loadValue(values, 0)
            let CONST_TX_TAG_NONCE := 1
            appendTxRow(txId, CONST_TX_TAG_NONCE, txNonce)
          }

          {
            let gasLimit := loadValue(values, 2)
            let CONST_TX_TAG_GAS := 2
            appendTxRow(txId, CONST_TX_TAG_GAS, gasLimit)
          }

          {
            let gasPrice := loadValue(values, 1)
            let CONST_TX_TAG_GAS_PRICE := 3
            appendTxRow(txId, CONST_TX_TAG_GAS_PRICE, gasPrice)
          }

          {
            let CONST_TX_TAG_CALLER_ADDRESS := 4
            appendTxRow(txId, CONST_TX_TAG_CALLER_ADDRESS, txFrom)
          }

          {
            let to, len := loadValueLen(values, 3)
            let CONST_TX_TAG_CALLEE_ADDRESS := 5
            appendTxRow(txId, CONST_TX_TAG_CALLEE_ADDRESS, to)

            let isCreate := iszero(len)
            let CONST_TX_TAG_IS_CREATE := 6
            appendTxRow(txId, CONST_TX_TAG_IS_CREATE, isCreate)
          }

          {
            let txValue := loadValue(values, 4)
            let CONST_TX_TAG_VALUE := 7
            appendTxRow(txId, CONST_TX_TAG_VALUE, txValue)
          }

          let txInputOffset, txInputLen := loadPair(values, 5)
          {
            // keep track of calldata bytes being written
            {
              let callframe := mload(96)
              // callframe.calldataBytes
              let offset := add(callframe, 128)
              mstore(offset, add(mload(offset), txInputLen))
            }

            let CONST_TX_TAG_CALL_DATA_LENGTH := 8
            appendTxRow(txId, CONST_TX_TAG_CALL_DATA_LENGTH, txInputLen)
          }

          // calldata part
          {
            let zeroBytes
            for { let i := 0 } lt(i, txInputLen) { i := add(i, 1) } {
              let val := byte(0, calldataload(add(txInputOffset, i)))
              appendCallDataRow(txId, i, val)

              zeroBytes := add(zeroBytes, iszero(val))
            }

            {
              let gasCost := add(mul(zeroBytes, 4), mul(sub(txInputLen, zeroBytes), 16))
              let CONST_TX_TAG_CALL_DATA_GAS := 9
              appendTxRow(txId, CONST_TX_TAG_CALL_DATA_GAS, gasCost)
            }
          }

          {
            let CONST_TX_TAG_SIGN_HASH := 10
            appendTxRow(txId, CONST_TX_TAG_SIGN_HASH, hash)
          }
        }

        require(eq(dataOffset, dataOffsetTail), "DATA")
        // verify callframe.calldataBytes
        {
          let callframe := mload(96)
          let value := mload(add(callframe, 128))
          require(
            or(
              eq(value, MAX_CALLDATA),
              lt(value, MAX_CALLDATA)
            ),
            "MAX_DATA"
          )
        }

        // MAX_TXS padding
        for {} lt(txId, MAX_TXS) { } {
          txId := add(txId, 1)

          // add tag field NONCE...SIG_HASH
          for { let tag := 1 } lt(tag, 11) { tag := add(tag, 1) } {
            appendTxRow(txId, tag, 0)
          }
        }

        require(eq(txId, MAX_TXS), "MAX_TXS")
      }

      // fix `row.q_end = 1`
      {
        let rpi := mload(32)
        // q_end
        mstore(sub(rpi, 64), 1)
        // q_not_end
        mstore(sub(rpi, 32), 0)
      }

      let NUM_RAW_INPUTS := sub(mload(64), mload(32))
      // hash(raw_public_inputs)
      let rand_rpi := mod(keccak256(mload(32), NUM_RAW_INPUTS), 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
      let rpi_rlc := 0
      {
        let raw_head := mload(32)
        let raw_tail := add(raw_head, NUM_RAW_INPUTS)

        for {} gt(raw_tail, raw_head) {} {
          raw_tail := sub(raw_tail, 32)
          let raw_value := mload(raw_tail)

          let p := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
          rpi_rlc := mulmod(rpi_rlc, rand_rpi, p)
          rpi_rlc := addmod(rpi_rlc, raw_value, p)
        }
      }

      // rpi_rlc_acc_col
      {
        let raw_head := mload(32)
        let raw_tail := add(raw_head, NUM_RAW_INPUTS)
        raw_tail := sub(raw_tail, 32)

        // rpi_rlc_acc_col = [raw_public_inputs[-1]]
        let rpi_rlc_acc := mload(raw_tail)
        // start offset = row.rand_rpi
        let row_tail := sub(raw_head, 96)
        {
          // store row.rand_rpi
          mstore(row_tail, rand_rpi)

          // store row.rpi_rlc_acc_col
          mstore(sub(row_tail, 32), rpi_rlc_acc)

          // store row.raw_public_inputs
          mstore(sub(row_tail, 64), rpi_rlc_acc)

          row_tail := sub(row_tail, 384)
        }

        // for i in reversed(range(len(raw_public_inputs) - 1)):
        for {} gt(raw_tail, raw_head) {} {
          raw_tail := sub(raw_tail, 32)
          let raw_value := mload(raw_tail)

          // rpi_rlc_acc_col[-1] * rand_rpi + raw_public_inputs[i]
          let p := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
          rpi_rlc_acc := mulmod(rpi_rlc_acc, rand_rpi, p)
          rpi_rlc_acc := addmod(rpi_rlc_acc, raw_value, p)

          // store row.rand_rpi
          mstore(row_tail, rand_rpi)

          // store row.rpi_rlc_acc_col
          mstore(sub(row_tail, 32), rpi_rlc_acc)

          // store row.raw_public_inputs
          mstore(sub(row_tail, 64), raw_value)

          // store row.q_not_end
          mstore(add(row_tail, 64), 1)

          row_tail := sub(row_tail, 384)
        }
      }

      // reset dirty slot
      mstore(96, 0)
      // move free memory pointer to end of table data
      mstore(64, mload(32))
      // return table uint256[]
      table := sub(table, 32)
    }
  }
}

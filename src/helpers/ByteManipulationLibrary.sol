// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.12;

library ByteManipulationLibrary {
    //position starts from zero
    function getFixedData(bytes calldata data, uint256 position) public pure returns (bytes memory) {
        uint256 initialPosition = position * 32;
        uint256 endingPosition = initialPosition + 32;
        return data[initialPosition:endingPosition];
    }

    function getDynamicData(bytes calldata data, uint256 position) public pure returns (bytes memory) {
        uint256 initialPosition = (position * 32);
        uint256 endingPosition = initialPosition + 32;
        uint256 dataPosition = uint256(bytes32(data[initialPosition:endingPosition]));

        uint256 dataStart = dataPosition;

        uint256 dataLengthEndPosition = dataStart + 32;

        uint256 length = uint256(bytes32(data[dataStart:dataLengthEndPosition]));
        bytes memory extractedData = new bytes(length);
        uint256 _start = dataLengthEndPosition;
        uint256 _end = _start + length;
        extractedData = data[_start:_end];
        return extractedData;
    }

    function getFixedSizeDynamicArrayData(bytes calldata data, uint256 position) public pure returns (bytes[] memory) {
        uint256 _start;
        uint256 _end;
        uint256 offset;
        uint256 dataPosition;
        uint256 dataPositionEnd;
        uint256 anchor;

        {
            uint256 initialPosition = (position * 32);
            uint256 endingPosition = initialPosition + 32;
            dataPosition = uint256(bytes32(data[initialPosition:endingPosition]));
            anchor = dataPosition;
            dataPositionEnd = dataPosition + 32;
            offset = uint256(bytes32(data[dataPosition:dataPositionEnd]));
            _start = anchor + offset;
            _end = _start + 32;
        }
        uint256 arrayElements = uint256(offset / 32);
        bytes[] memory extractedData = new bytes[](arrayElements);
        {
            for (uint256 i = 0; i < arrayElements; i++) {
                uint256 elementLength = uint256(bytes32(data[_start:_end]));
                bytes memory element = bytes(data[_end:_end + elementLength]);
                extractedData[i] = bytes(element);
                dataPosition = dataPositionEnd;
                dataPositionEnd = dataPosition + 32;
                offset = uint256(bytes32(data[dataPosition:dataPositionEnd]));
                _start = anchor + offset;
                _end = _start + 32;
            }
        }
        return extractedData;
    }

    function getStaticArrayData(bytes calldata data, uint256 position) public pure returns (bytes[] memory) {
        uint256 initialPosition = (position * 32);
        uint256 endingPosition = initialPosition + 32;
        uint256 dataPosition = uint256(bytes32(data[initialPosition:endingPosition]));

        uint256 dataStart = dataPosition;

        uint256 dataLengthEndPosition = dataStart + 32;

        uint256 length = uint256(bytes32(data[dataStart:dataLengthEndPosition]));
        bytes[] memory extractedData = new bytes[](length);
        uint256 _start = dataLengthEndPosition;
        uint256 _end = _start + 32;
        for (uint256 i = 0; i < length; i++) {
            extractedData[i] = data[_start:_end];
            _start = _end;
            _end = _start + 32;
        }
        return extractedData;
    }

    function getDynamicSizeDynamicArrayData(bytes calldata data, uint256 position)
        public
        pure
        returns (bytes[] memory)
    {
        uint256 _start;
        uint256 _end;
        uint256 offset;
        uint256 dataPosition;
        uint256 dataPositionEnd;
        uint256 anchor;
        uint256 arrayElements;

        {
            uint256 initialPosition = (position * 32);
            uint256 endingPosition = initialPosition + 32;

            uint256 lengthValueStart = uint256(bytes32(data[initialPosition:endingPosition]));
            uint256 lengthValueEnd = lengthValueStart + 32;
            arrayElements = uint256(bytes32(data[lengthValueStart:lengthValueEnd]));
            dataPosition = lengthValueEnd;
            dataPositionEnd = dataPosition + 32;
            anchor = lengthValueEnd;
            offset = uint256(bytes32(data[dataPosition:dataPositionEnd]));
            _start = anchor + offset;
            _end = _start + 32;
        }
        bytes[] memory extractedData = new bytes[](arrayElements);
        {
            for (uint256 i = 0; i < arrayElements; i++) {
                uint256 elementLength = uint256(bytes32(data[_start:_end]));
                bytes memory element = bytes(data[_end:_end + elementLength]);
                extractedData[i] = bytes(element);
                dataPosition = dataPositionEnd;
                dataPositionEnd = dataPosition + 32;
                offset = uint256(bytes32(data[dataPosition:dataPositionEnd]));
                _start = anchor + offset;
                _end = _start + 32;
            }
        }
        return extractedData;
    }
}

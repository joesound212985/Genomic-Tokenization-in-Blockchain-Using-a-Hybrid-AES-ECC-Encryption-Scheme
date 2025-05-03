// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileStorage {
    struct File {
        string encryptedIpfsHash;
        string encryptedAesKey;
        address fileOwner;
        uint256 timestamp;
    }

    File[] public files;
    mapping(uint256 => mapping(address => bool)) private accessControl;

    event FileAdded(uint256 indexed fileIndex, address indexed fileOwner, uint256 timestamp);
    event AccessGranted(uint256 indexed fileIndex, address indexed grantedAddress);
    event AccessRevoked(uint256 indexed fileIndex, address indexed revokedAddress);

    function addFile(string memory _encryptedIpfsHash, string memory _encryptedAesKey) public {
        files.push(File(_encryptedIpfsHash, _encryptedAesKey, msg.sender, block.timestamp));
        uint256 fileIndex = files.length - 1;
        accessControl[fileIndex][msg.sender] = true;
        emit FileAdded(fileIndex, msg.sender, block.timestamp);
    }

    function getFile(uint256 _fileIndex) public view returns (string memory, string memory) {
        require(_fileIndex < files.length, "Invalid file index");
        File memory file = files[_fileIndex];
        require(msg.sender == file.fileOwner || accessControl[_fileIndex][msg.sender], "Access denied");
        return (file.encryptedIpfsHash, file.encryptedAesKey);
    }

    function getFilesCount() public view returns (uint256) {
        return files.length;
    }

    function grantAccess(address _address, uint256 _fileIndex) public {
        require(_fileIndex < files.length, "Invalid file index");
        File memory file = files[_fileIndex];
        require(msg.sender == file.fileOwner, "Only file owner can grant access");
        accessControl[_fileIndex][_address] = true;
        emit AccessGranted(_fileIndex, _address);
    }

    function revokeAccess(address _address, uint256 _fileIndex) public {
        require(_fileIndex < files.length, "Invalid file index");
        File memory file = files[_fileIndex];
        require(msg.sender == file.fileOwner, "Only file owner can revoke access");
        accessControl[_fileIndex][_address] = false;
        emit AccessRevoked(_fileIndex, _address);
    }

    function hasAccess(address _address, uint256 _fileIndex) public view returns (bool) {
        require(_fileIndex < files.length, "Invalid file index");
        return accessControl[_fileIndex][_address];
    }

    function getFileInfo(uint256 _fileIndex) public view returns (string memory, string memory, address, uint256) {
        require(_fileIndex < files.length, "Invalid file index");
        File memory file = files[_fileIndex];
        return (file.encryptedIpfsHash, file.encryptedAesKey, file.fileOwner, file.timestamp);
    }

    function getAccessList(uint256 _fileIndex) public view returns (address[] memory) {
        require(_fileIndex < files.length, "Invalid file index");
        address[] memory accessList = new address[](files.length);
        uint256 count = 0;
        
        for (uint256 i = 0; i < files.length; i++) {
            if (accessControl[_fileIndex][files[i].fileOwner]) {
                accessList[count] = files[i].fileOwner;
                count++;
            }
        }
        
        // Resize the array to the actual number of addresses with access
        assembly {
            mstore(accessList, count)
        }
        
        return accessList;
    }
}
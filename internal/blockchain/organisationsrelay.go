// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package blockchain

import (
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = abi.U256
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// OrganisationsRelayABI is the input ABI used to generate the binding from.
const OrganisationsRelayABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"organisationsContract\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getOrganisationByIndex\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"address[]\"},{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"hash\",\"type\":\"bytes32\"}],\"name\":\"getOrganisationByHash\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"address[]\"},{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"id\",\"type\":\"string\"}],\"name\":\"removeOrganisation\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"id\",\"type\":\"string\"}],\"name\":\"getOrganisation\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"address[]\"},{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getOrganisationCount\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"createdAt\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"id\",\"type\":\"string\"},{\"name\":\"members\",\"type\":\"address[]\"}],\"name\":\"setMembers\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"id\",\"type\":\"string\"},{\"name\":\"organisationOwner\",\"type\":\"address\"}],\"name\":\"changeOrganisationOwner\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"oldId\",\"type\":\"string\"},{\"name\":\"newId\",\"type\":\"string\"}],\"name\":\"renameOrganisation\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"id\",\"type\":\"string\"},{\"name\":\"organisationOwner\",\"type\":\"address\"}],\"name\":\"addOrganisation\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"oContract\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

// OrganisationsRelay is an auto generated Go binding around an Ethereum contract.
type OrganisationsRelay struct {
	OrganisationsRelayCaller     // Read-only binding to the contract
	OrganisationsRelayTransactor // Write-only binding to the contract
	OrganisationsRelayFilterer   // Log filterer for contract events
}

// OrganisationsRelayCaller is an auto generated read-only Go binding around an Ethereum contract.
type OrganisationsRelayCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OrganisationsRelayTransactor is an auto generated write-only Go binding around an Ethereum contract.
type OrganisationsRelayTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OrganisationsRelayFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type OrganisationsRelayFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OrganisationsRelaySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type OrganisationsRelaySession struct {
	Contract     *OrganisationsRelay // Generic contract binding to set the session for
	CallOpts     bind.CallOpts       // Call options to use throughout this session
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// OrganisationsRelayCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type OrganisationsRelayCallerSession struct {
	Contract *OrganisationsRelayCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts             // Call options to use throughout this session
}

// OrganisationsRelayTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type OrganisationsRelayTransactorSession struct {
	Contract     *OrganisationsRelayTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts             // Transaction auth options to use throughout this session
}

// OrganisationsRelayRaw is an auto generated low-level Go binding around an Ethereum contract.
type OrganisationsRelayRaw struct {
	Contract *OrganisationsRelay // Generic contract binding to access the raw methods on
}

// OrganisationsRelayCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type OrganisationsRelayCallerRaw struct {
	Contract *OrganisationsRelayCaller // Generic read-only contract binding to access the raw methods on
}

// OrganisationsRelayTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type OrganisationsRelayTransactorRaw struct {
	Contract *OrganisationsRelayTransactor // Generic write-only contract binding to access the raw methods on
}

// NewOrganisationsRelay creates a new instance of OrganisationsRelay, bound to a specific deployed contract.
func NewOrganisationsRelay(address common.Address, backend bind.ContractBackend) (*OrganisationsRelay, error) {
	contract, err := bindOrganisationsRelay(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &OrganisationsRelay{OrganisationsRelayCaller: OrganisationsRelayCaller{contract: contract}, OrganisationsRelayTransactor: OrganisationsRelayTransactor{contract: contract}, OrganisationsRelayFilterer: OrganisationsRelayFilterer{contract: contract}}, nil
}

// NewOrganisationsRelayCaller creates a new read-only instance of OrganisationsRelay, bound to a specific deployed contract.
func NewOrganisationsRelayCaller(address common.Address, caller bind.ContractCaller) (*OrganisationsRelayCaller, error) {
	contract, err := bindOrganisationsRelay(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &OrganisationsRelayCaller{contract: contract}, nil
}

// NewOrganisationsRelayTransactor creates a new write-only instance of OrganisationsRelay, bound to a specific deployed contract.
func NewOrganisationsRelayTransactor(address common.Address, transactor bind.ContractTransactor) (*OrganisationsRelayTransactor, error) {
	contract, err := bindOrganisationsRelay(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &OrganisationsRelayTransactor{contract: contract}, nil
}

// NewOrganisationsRelayFilterer creates a new log filterer instance of OrganisationsRelay, bound to a specific deployed contract.
func NewOrganisationsRelayFilterer(address common.Address, filterer bind.ContractFilterer) (*OrganisationsRelayFilterer, error) {
	contract, err := bindOrganisationsRelay(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &OrganisationsRelayFilterer{contract: contract}, nil
}

// bindOrganisationsRelay binds a generic wrapper to an already deployed contract.
func bindOrganisationsRelay(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(OrganisationsRelayABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_OrganisationsRelay *OrganisationsRelayRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _OrganisationsRelay.Contract.OrganisationsRelayCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_OrganisationsRelay *OrganisationsRelayRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.OrganisationsRelayTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_OrganisationsRelay *OrganisationsRelayRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.OrganisationsRelayTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_OrganisationsRelay *OrganisationsRelayCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _OrganisationsRelay.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_OrganisationsRelay *OrganisationsRelayTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_OrganisationsRelay *OrganisationsRelayTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.contract.Transact(opts, method, params...)
}

// CreatedAt is a free data retrieval call binding the contract method 0xcf09e0d0.
//
// Solidity: function createdAt() constant returns(uint256)
func (_OrganisationsRelay *OrganisationsRelayCaller) CreatedAt(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _OrganisationsRelay.contract.Call(opts, out, "createdAt")
	return *ret0, err
}

// CreatedAt is a free data retrieval call binding the contract method 0xcf09e0d0.
//
// Solidity: function createdAt() constant returns(uint256)
func (_OrganisationsRelay *OrganisationsRelaySession) CreatedAt() (*big.Int, error) {
	return _OrganisationsRelay.Contract.CreatedAt(&_OrganisationsRelay.CallOpts)
}

// CreatedAt is a free data retrieval call binding the contract method 0xcf09e0d0.
//
// Solidity: function createdAt() constant returns(uint256)
func (_OrganisationsRelay *OrganisationsRelayCallerSession) CreatedAt() (*big.Int, error) {
	return _OrganisationsRelay.Contract.CreatedAt(&_OrganisationsRelay.CallOpts)
}

// GetOrganisation is a free data retrieval call binding the contract method 0x50a38744.
//
// Solidity: function getOrganisation(string id) constant returns(address, address[], string, uint256)
func (_OrganisationsRelay *OrganisationsRelayCaller) GetOrganisation(opts *bind.CallOpts, id string) (common.Address, []common.Address, string, *big.Int, error) {
	var (
		ret0 = new(common.Address)
		ret1 = new([]common.Address)
		ret2 = new(string)
		ret3 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
		ret1,
		ret2,
		ret3,
	}
	err := _OrganisationsRelay.contract.Call(opts, out, "getOrganisation", id)
	return *ret0, *ret1, *ret2, *ret3, err
}

// GetOrganisation is a free data retrieval call binding the contract method 0x50a38744.
//
// Solidity: function getOrganisation(string id) constant returns(address, address[], string, uint256)
func (_OrganisationsRelay *OrganisationsRelaySession) GetOrganisation(id string) (common.Address, []common.Address, string, *big.Int, error) {
	return _OrganisationsRelay.Contract.GetOrganisation(&_OrganisationsRelay.CallOpts, id)
}

// GetOrganisation is a free data retrieval call binding the contract method 0x50a38744.
//
// Solidity: function getOrganisation(string id) constant returns(address, address[], string, uint256)
func (_OrganisationsRelay *OrganisationsRelayCallerSession) GetOrganisation(id string) (common.Address, []common.Address, string, *big.Int, error) {
	return _OrganisationsRelay.Contract.GetOrganisation(&_OrganisationsRelay.CallOpts, id)
}

// GetOrganisationByHash is a free data retrieval call binding the contract method 0x06e80cd9.
//
// Solidity: function getOrganisationByHash(bytes32 hash) constant returns(address, address[], string, uint256)
func (_OrganisationsRelay *OrganisationsRelayCaller) GetOrganisationByHash(opts *bind.CallOpts, hash [32]byte) (common.Address, []common.Address, string, *big.Int, error) {
	var (
		ret0 = new(common.Address)
		ret1 = new([]common.Address)
		ret2 = new(string)
		ret3 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
		ret1,
		ret2,
		ret3,
	}
	err := _OrganisationsRelay.contract.Call(opts, out, "getOrganisationByHash", hash)
	return *ret0, *ret1, *ret2, *ret3, err
}

// GetOrganisationByHash is a free data retrieval call binding the contract method 0x06e80cd9.
//
// Solidity: function getOrganisationByHash(bytes32 hash) constant returns(address, address[], string, uint256)
func (_OrganisationsRelay *OrganisationsRelaySession) GetOrganisationByHash(hash [32]byte) (common.Address, []common.Address, string, *big.Int, error) {
	return _OrganisationsRelay.Contract.GetOrganisationByHash(&_OrganisationsRelay.CallOpts, hash)
}

// GetOrganisationByHash is a free data retrieval call binding the contract method 0x06e80cd9.
//
// Solidity: function getOrganisationByHash(bytes32 hash) constant returns(address, address[], string, uint256)
func (_OrganisationsRelay *OrganisationsRelayCallerSession) GetOrganisationByHash(hash [32]byte) (common.Address, []common.Address, string, *big.Int, error) {
	return _OrganisationsRelay.Contract.GetOrganisationByHash(&_OrganisationsRelay.CallOpts, hash)
}

// GetOrganisationByIndex is a free data retrieval call binding the contract method 0x04fc1902.
//
// Solidity: function getOrganisationByIndex(uint256 index) constant returns(address, address[], string, uint256)
func (_OrganisationsRelay *OrganisationsRelayCaller) GetOrganisationByIndex(opts *bind.CallOpts, index *big.Int) (common.Address, []common.Address, string, *big.Int, error) {
	var (
		ret0 = new(common.Address)
		ret1 = new([]common.Address)
		ret2 = new(string)
		ret3 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
		ret1,
		ret2,
		ret3,
	}
	err := _OrganisationsRelay.contract.Call(opts, out, "getOrganisationByIndex", index)
	return *ret0, *ret1, *ret2, *ret3, err
}

// GetOrganisationByIndex is a free data retrieval call binding the contract method 0x04fc1902.
//
// Solidity: function getOrganisationByIndex(uint256 index) constant returns(address, address[], string, uint256)
func (_OrganisationsRelay *OrganisationsRelaySession) GetOrganisationByIndex(index *big.Int) (common.Address, []common.Address, string, *big.Int, error) {
	return _OrganisationsRelay.Contract.GetOrganisationByIndex(&_OrganisationsRelay.CallOpts, index)
}

// GetOrganisationByIndex is a free data retrieval call binding the contract method 0x04fc1902.
//
// Solidity: function getOrganisationByIndex(uint256 index) constant returns(address, address[], string, uint256)
func (_OrganisationsRelay *OrganisationsRelayCallerSession) GetOrganisationByIndex(index *big.Int) (common.Address, []common.Address, string, *big.Int, error) {
	return _OrganisationsRelay.Contract.GetOrganisationByIndex(&_OrganisationsRelay.CallOpts, index)
}

// GetOrganisationCount is a free data retrieval call binding the contract method 0xb082b9c7.
//
// Solidity: function getOrganisationCount() constant returns(uint256)
func (_OrganisationsRelay *OrganisationsRelayCaller) GetOrganisationCount(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _OrganisationsRelay.contract.Call(opts, out, "getOrganisationCount")
	return *ret0, err
}

// GetOrganisationCount is a free data retrieval call binding the contract method 0xb082b9c7.
//
// Solidity: function getOrganisationCount() constant returns(uint256)
func (_OrganisationsRelay *OrganisationsRelaySession) GetOrganisationCount() (*big.Int, error) {
	return _OrganisationsRelay.Contract.GetOrganisationCount(&_OrganisationsRelay.CallOpts)
}

// GetOrganisationCount is a free data retrieval call binding the contract method 0xb082b9c7.
//
// Solidity: function getOrganisationCount() constant returns(uint256)
func (_OrganisationsRelay *OrganisationsRelayCallerSession) GetOrganisationCount() (*big.Int, error) {
	return _OrganisationsRelay.Contract.GetOrganisationCount(&_OrganisationsRelay.CallOpts)
}

// OrganisationsContract is a free data retrieval call binding the contract method 0x03a4692a.
//
// Solidity: function organisationsContract() constant returns(address)
func (_OrganisationsRelay *OrganisationsRelayCaller) OrganisationsContract(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _OrganisationsRelay.contract.Call(opts, out, "organisationsContract")
	return *ret0, err
}

// OrganisationsContract is a free data retrieval call binding the contract method 0x03a4692a.
//
// Solidity: function organisationsContract() constant returns(address)
func (_OrganisationsRelay *OrganisationsRelaySession) OrganisationsContract() (common.Address, error) {
	return _OrganisationsRelay.Contract.OrganisationsContract(&_OrganisationsRelay.CallOpts)
}

// OrganisationsContract is a free data retrieval call binding the contract method 0x03a4692a.
//
// Solidity: function organisationsContract() constant returns(address)
func (_OrganisationsRelay *OrganisationsRelayCallerSession) OrganisationsContract() (common.Address, error) {
	return _OrganisationsRelay.Contract.OrganisationsContract(&_OrganisationsRelay.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_OrganisationsRelay *OrganisationsRelayCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _OrganisationsRelay.contract.Call(opts, out, "owner")
	return *ret0, err
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_OrganisationsRelay *OrganisationsRelaySession) Owner() (common.Address, error) {
	return _OrganisationsRelay.Contract.Owner(&_OrganisationsRelay.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_OrganisationsRelay *OrganisationsRelayCallerSession) Owner() (common.Address, error) {
	return _OrganisationsRelay.Contract.Owner(&_OrganisationsRelay.CallOpts)
}

// AddOrganisation is a paid mutator transaction binding the contract method 0xfe794b00.
//
// Solidity: function addOrganisation(string id, address organisationOwner) returns()
func (_OrganisationsRelay *OrganisationsRelayTransactor) AddOrganisation(opts *bind.TransactOpts, id string, organisationOwner common.Address) (*types.Transaction, error) {
	return _OrganisationsRelay.contract.Transact(opts, "addOrganisation", id, organisationOwner)
}

// AddOrganisation is a paid mutator transaction binding the contract method 0xfe794b00.
//
// Solidity: function addOrganisation(string id, address organisationOwner) returns()
func (_OrganisationsRelay *OrganisationsRelaySession) AddOrganisation(id string, organisationOwner common.Address) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.AddOrganisation(&_OrganisationsRelay.TransactOpts, id, organisationOwner)
}

// AddOrganisation is a paid mutator transaction binding the contract method 0xfe794b00.
//
// Solidity: function addOrganisation(string id, address organisationOwner) returns()
func (_OrganisationsRelay *OrganisationsRelayTransactorSession) AddOrganisation(id string, organisationOwner common.Address) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.AddOrganisation(&_OrganisationsRelay.TransactOpts, id, organisationOwner)
}

// ChangeOrganisationOwner is a paid mutator transaction binding the contract method 0xf26937b5.
//
// Solidity: function changeOrganisationOwner(string id, address organisationOwner) returns()
func (_OrganisationsRelay *OrganisationsRelayTransactor) ChangeOrganisationOwner(opts *bind.TransactOpts, id string, organisationOwner common.Address) (*types.Transaction, error) {
	return _OrganisationsRelay.contract.Transact(opts, "changeOrganisationOwner", id, organisationOwner)
}

// ChangeOrganisationOwner is a paid mutator transaction binding the contract method 0xf26937b5.
//
// Solidity: function changeOrganisationOwner(string id, address organisationOwner) returns()
func (_OrganisationsRelay *OrganisationsRelaySession) ChangeOrganisationOwner(id string, organisationOwner common.Address) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.ChangeOrganisationOwner(&_OrganisationsRelay.TransactOpts, id, organisationOwner)
}

// ChangeOrganisationOwner is a paid mutator transaction binding the contract method 0xf26937b5.
//
// Solidity: function changeOrganisationOwner(string id, address organisationOwner) returns()
func (_OrganisationsRelay *OrganisationsRelayTransactorSession) ChangeOrganisationOwner(id string, organisationOwner common.Address) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.ChangeOrganisationOwner(&_OrganisationsRelay.TransactOpts, id, organisationOwner)
}

// RemoveOrganisation is a paid mutator transaction binding the contract method 0x13ed4cb6.
//
// Solidity: function removeOrganisation(string id) returns()
func (_OrganisationsRelay *OrganisationsRelayTransactor) RemoveOrganisation(opts *bind.TransactOpts, id string) (*types.Transaction, error) {
	return _OrganisationsRelay.contract.Transact(opts, "removeOrganisation", id)
}

// RemoveOrganisation is a paid mutator transaction binding the contract method 0x13ed4cb6.
//
// Solidity: function removeOrganisation(string id) returns()
func (_OrganisationsRelay *OrganisationsRelaySession) RemoveOrganisation(id string) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.RemoveOrganisation(&_OrganisationsRelay.TransactOpts, id)
}

// RemoveOrganisation is a paid mutator transaction binding the contract method 0x13ed4cb6.
//
// Solidity: function removeOrganisation(string id) returns()
func (_OrganisationsRelay *OrganisationsRelayTransactorSession) RemoveOrganisation(id string) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.RemoveOrganisation(&_OrganisationsRelay.TransactOpts, id)
}

// RenameOrganisation is a paid mutator transaction binding the contract method 0xf4e1bb87.
//
// Solidity: function renameOrganisation(string oldId, string newId) returns()
func (_OrganisationsRelay *OrganisationsRelayTransactor) RenameOrganisation(opts *bind.TransactOpts, oldId string, newId string) (*types.Transaction, error) {
	return _OrganisationsRelay.contract.Transact(opts, "renameOrganisation", oldId, newId)
}

// RenameOrganisation is a paid mutator transaction binding the contract method 0xf4e1bb87.
//
// Solidity: function renameOrganisation(string oldId, string newId) returns()
func (_OrganisationsRelay *OrganisationsRelaySession) RenameOrganisation(oldId string, newId string) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.RenameOrganisation(&_OrganisationsRelay.TransactOpts, oldId, newId)
}

// RenameOrganisation is a paid mutator transaction binding the contract method 0xf4e1bb87.
//
// Solidity: function renameOrganisation(string oldId, string newId) returns()
func (_OrganisationsRelay *OrganisationsRelayTransactorSession) RenameOrganisation(oldId string, newId string) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.RenameOrganisation(&_OrganisationsRelay.TransactOpts, oldId, newId)
}

// SetMembers is a paid mutator transaction binding the contract method 0xd317f35f.
//
// Solidity: function setMembers(string id, address[] members) returns()
func (_OrganisationsRelay *OrganisationsRelayTransactor) SetMembers(opts *bind.TransactOpts, id string, members []common.Address) (*types.Transaction, error) {
	return _OrganisationsRelay.contract.Transact(opts, "setMembers", id, members)
}

// SetMembers is a paid mutator transaction binding the contract method 0xd317f35f.
//
// Solidity: function setMembers(string id, address[] members) returns()
func (_OrganisationsRelay *OrganisationsRelaySession) SetMembers(id string, members []common.Address) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.SetMembers(&_OrganisationsRelay.TransactOpts, id, members)
}

// SetMembers is a paid mutator transaction binding the contract method 0xd317f35f.
//
// Solidity: function setMembers(string id, address[] members) returns()
func (_OrganisationsRelay *OrganisationsRelayTransactorSession) SetMembers(id string, members []common.Address) (*types.Transaction, error) {
	return _OrganisationsRelay.Contract.SetMembers(&_OrganisationsRelay.TransactOpts, id, members)
}


````
Python Implementation RLP encode/decode for Node Discovery protocol. Recursive Length
Prefix (RLP) is the serialization format that Ethereum uses to serialize objects to raw
bytes, used extensively in Ethereum's execution clients. The RLP specification only
understands two data primitives(item, list of items). This is  excensively used from
Merkle Patricia Tree (keys are encoded with RLP) to peer-to-peer communications between
nodes with RLPx (message data are encoded with RLP). 

References:
- The Ethereum Community: The Ethereum Wiki. Page 21, RLP: 
  https://github.com/ethereum/wiki
- Whitepaper: https://ethereum.github.io/yellowpaper/paper.pdf#page=19. 
- https://ethereum.org/developers/docs/data-structures-and-encoding/rlp
- https://medium.com/coinmonks/ethereum-under-the-hood-part-3-rlp-decoding-df236dc13e58
````

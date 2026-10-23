let rpc = "https://api.devnet.solana.com";
let method = "getBalance";
let path = "/";
let body = '{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["7gNqCpGKvGjMqfPnYrTcJqJqCmBvqPbRqXqPbRqXqP"]}'

import { post } from "@stdlib/http";
let resp = post(rpc, {body: body, headers: {"Content-Type": "application/json"}});
let data = JSON.parse(resp.body);
print("Devnet balance: " + data.result.value);

const http = require('http');

const PORT = process.env.PORT || 3001;

// Simple mock SSE MCP server for testing
const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);
  
  if (req.url === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Mock SSE MCP Server');
  } else if (req.url === '/sse' && req.method === 'GET') {
    // SSE endpoint
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });
    
    // Send initial endpoint message
    res.write('data: {"jsonrpc":"2.0","method":"endpoint","params":{"type":"endpoint","url":"/message"}}\n\n');
    
    // Keep connection alive
    const keepAlive = setInterval(() => {
      res.write(':keepalive\n\n');
    }, 30000);
    
    req.on('close', () => {
      clearInterval(keepAlive);
    });
  } else if (req.url === '/message' && req.method === 'POST') {
    // Message endpoint
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const request = JSON.parse(body);
        console.log('Received request:', request);
        
        let response;
        if (request.method === 'tools/list') {
          response = {
            jsonrpc: '2.0',
            id: request.id,
            result: {
              tools: [
                {
                  name: 'echo_text',
                  description: 'Echo the provided text',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      text: { type: 'string' }
                    },
                    required: ['text']
                  }
                },
                {
                  name: 'sample_stream',
                  description: 'Sample streaming tool',
                  inputSchema: {
                    type: 'object',
                    properties: {}
                  }
                }
              ]
            }
          };
        } else if (request.method === 'tools/call') {
          if (request.params.name === 'echo_text') {
            response = {
              jsonrpc: '2.0',
              id: request.id,
              result: {
                toolResult: request.params.arguments.text
              }
            };
          } else if (request.params.name === 'non_existent_tool_xyz') {
            response = {
              jsonrpc: '2.0',
              id: request.id,
              error: {
                code: -32601,
                message: 'Tool not found: ' + request.params.name
              }
            };
          } else {
            response = {
              jsonrpc: '2.0',
              id: request.id,
              result: {
                toolResult: 'Tool executed successfully'
              }
            };
          }
        } else {
          response = {
            jsonrpc: '2.0',
            id: request.id,
            result: {}
          };
        }
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response));
      } catch (e) {
        console.error('Error processing request:', e);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32700,
            message: 'Parse error'
          }
        }));
      }
    });
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  }
});

server.listen(PORT, () => {
  console.log(`Mock SSE MCP server listening on port ${PORT}`);
});
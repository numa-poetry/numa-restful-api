# Numa RESTful API

## What?
"Numa" is derived from "pneúma", meaning wind, breath, spirit. Numa's API provides functionality for sharing poetry, gathering feedback, and connecting with others.

## Why?
I'm developing Numa because I care about connecting with people; sharing expressive works with my friends and family; and having a clean, dynamic, and modern web application for sharing any form of lyrical expression.

## Okay, how do I get the server running?
* Download and install [Node.js](http://www.nodejs.org/download/). You can also follow [this gist](https://gist.github.com/isaacs/579814) for a quick and easy way to install Node.js and npm
* Download and install [Node.js package manager](https://github.com/npm/npm).
* Download and install [MongoDB](http://docs.mongodb.org/manual/installation/) - Make sure `mongod` is running on the default port (27017).
* Install [nodemon](http://nodemon.io/): `npm install -g nodemon`
* Clone the repo: `git clone https://github.com/boyz-2-men/numa-restful-api.git`
* Install packages: `npm install`
* Rename pub-auth.js to auth.js in config/ and add in your own secrets.
* Launch server: `nodemon .\server.js`. 
* Visit `http://localhost:3000` or hit the endpoints using a client like the [Advanced REST Client](https://chrome.google.com/webstore/detail/advanced-rest-client/hgmloofddffdnphfgcellkdfbfbjeloo?hl=en-US) Chrome extension

## Where can I see the documentation?
I'll be adding the RESTful API docs at [ReadMe.io](http://numa.readme.io/v1.0)

### License

The MIT License (MIT)

Copyright (c) [year] [fullname]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

# CS3700 Project 4 - Web Crawler

## High Level Approach

The crawler is a simple single thread loop of requesting, parsing and updating internal state. HashMaps are used for keeping track of visited sites and discovered flags.

## Challenges faced

Chunked encoding proved to be difficult as the sequential nature of it breaks my initial abstraction of receive -> parse, so the underlying stream needs to be passed to the decoding function, which is not ideal. 

## Testing

Code is tested on Windows. RUST_LOG=debug will provide detailed logging.

## External Libraries Used

html5ever - HTML parsing

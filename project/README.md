# Project 2: Security
### Name: Arsh Malik
### UID: 605723801
## Description of Work

### Design Choices

This project focused on implementing a security layer on top of the reliable data transfer protocol developed in Project 1. The security layer aims to provide confidentiality, integrity, and authentication for the data exchanged between the client and server. Although most of the heavy lifting was done by the files provided, my implementations went into `sec.c`. An important aspect of this project was to understand the files provided, especially `security.h` and `security.c`, to understand how to utilize the functions in `sec.c`. Some important design choices include:

- **Insertion of data into the buffer**: The `insert_type` and `insert_length` functions were implemented to insert the type and length of the data into the buffer before the actual data. This ensures that we reduce any potential errors in data insertion.

- **Buffer pointer**: The `buffer` variable was used to keep track of the current position in the buffer while reading or writing data. This pointer is updated after each read or write operation to ensure that the next operation starts from the correct position. It was important to use a separate buffer than `buf` to avoid pointer arithmetic errors and ensure that the buffer is correctly updated.

### Problems Encountered

Although implementing the security layer was relatively straightforward, one common issue I faced was with pointer arithmetic. Although I was careful with my calculations, there were instances where I had off-by-one errors that caused segmentation faults or incorrect data processing.

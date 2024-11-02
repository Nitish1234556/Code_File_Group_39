#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "md5.c"      //this include the md5 hash function

//a pointer take three argument one char , second length , third output hash
typedef int (*Hash_Function)(unsigned char *, unsigned int, unsigned char *);


//this is the structure defination to the node of the merkle tree
typedef struct {
    char *hash;       //pointer to hash value
    char *data;       //pointer to data
}node;


//this is a structure defination to merkle tree
typedef struct {
    size_t n;                    // total number of nodes
    size_t h;                    // height of merkle tree
    size_t hash_size;            // size of hash
    size_t data_block_size;      // size of each data block
    size_t data_blocks;         // number of data blocks
    Hash_Function hash_function; // hash function
    node *nodes;     // Array of merkle nodes
} merkle_tree;


//build merkle tree mt
int make_tree(merkle_tree *mt, char **data);

//Function for the comparison of two merkle trees of size i
int comp_tree(merkle_tree *a, merkle_tree *b, size_t i);

//when we altered data then it construct merkle tree
int new_data(merkle_tree *mt, size_t block_num, char *data);

//freed up memory to avoid any leakage and well functioning of code
void free_Tree_space(merkle_tree *mt);

//it will calculate hash of specific node
static int hash_node(merkle_tree *mt, size_t i);

//it will print tree
static void print_tree(merkle_tree *mt);

//it will print original data before tampering
void print_org_data(char **original_data, size_t n);

//this is a function to print the original data
void print_org_data(char **original_data, size_t n);

//defining block size
#define BLOCK_SIZE 1024

//function to build merkle tree
int make_tree(merkle_tree *mt, char **data) {
    int i;
    int start_leaf;

    start_leaf = (int)pow(2, mt->h - 1);           //we will calculate the starting index for leaf nodes which is equal to 2^(h-1)
    mt->n = start_leaf + mt->data_blocks - 1;     //now we will calculate the total number of nodes

    // Allocate memory for nodes
    mt->nodes = (node *)malloc(sizeof(node) * (mt->n + 1));

    
    //now we will set up leaf nodes of the merkle tree
    for (i = start_leaf; i < start_leaf + mt->data_blocks; i++) {
        mt->nodes[i].data = data[i - start_leaf];      //store data
        mt->nodes[i].hash = NULL;                     //setting hash pointer as NULL
        if (hash_node(mt, i) == -1)                  //now call hash_node , -1 means hash is not calculated
            return -1;
    }

    //now we will calculate hash for internal nodes
    for (i = start_leaf - 1; i > 0; i--) {
        mt->nodes[i].hash = NULL;
        if (hash_node(mt, i) == -1)
            return -1;
    }

    return 0;
}


//this is a function to compare two merkle trees
int comp_tree(merkle_tree *a, merkle_tree *b, size_t i) {
    
    if (i > (size_t)pow(2, a->h) - 1){   //check whether i is within index or not
        return -1;}
    
    if (memcmp(a->nodes[i].hash, b->nodes[i].hash, a->hash_size) != 0) {  //using memcmp to compare nodes
        
        if (2 * i > (size_t)pow(2, a->h) - 1){          //checking whether the node is leaf node or not
            return i - (size_t)pow(2, a->h - 1) + 1;  //if leaf node then directly return
        }

        else {                                          //else recursively call for left child and right child
            
            int cmp = comp_tree(a, b, 2 * i);            //for left child of i
            if (cmp == 0){
                return comp_tree(a, b, 2 * i + 1);     //for right child of i
            }
            else
                return cmp;
        }
    }
    return 0;
}


//it will set tree data with a specific block number
int new_data(merkle_tree *mt, size_t block_num, char *data) {
    
    if (block_num > mt->data_blocks){  //checking for validity of block_num
        return -1;
    }
    size_t i = (size_t)pow(2, mt->h - 1) + block_num - 1;  //check for leaf node corresponding to given block
    
    if (mt->nodes[i].data){            //free data of that node 
        free(mt->nodes[i].data);
    }
    mt->nodes[i].data = data;         //change with the new data 
    
    if (hash_node(mt, i) == -1){      //now we will calculate hash of that node
        return -1;
    }
    for (i >>= 1; i > 0; i >>= 1) 
        if (hash_node(mt, i) == -1) 
            return -1; 
    return 0;
}


//this is a function to free up the space used by merkle tree 
void free_Tree_space(merkle_tree *mt) { //Checking if teh merkle tree is NULL
    if (!mt){                        //if merkle tree is NULL then do nothing
        return;
    }
    if (mt->nodes){                               // if nodes are not NULL  
        for (int i = 1; i <= mt->n; i++)          //free all hashes
            if (mt->nodes[i].hash) 
                free(mt->nodes[i].hash);
        free(mt->nodes);
    }
}


//function to calculate hash according to leaf node or internal node
static int hash_node(merkle_tree *mt, size_t i) {
    
    if (i > (size_t)(pow(2, mt->h) - 1)){         //validity of index
        return -1;
    }
    if (i < (size_t)pow(2, mt->h - 1)){          //if i is less than first leaf node then it is internal node
        
        if (2 * i + 1 <= mt->n && mt->nodes[2 * i].hash && mt->nodes[2 * i + 1].hash) {   //check whether it has both left and right child
            
            char *buffer = (char *)malloc(sizeof(char) * (2 * mt->hash_size + 1));        //allocate memory for a buffer which will take concatenate buffer of left and right child
            memcpy(buffer, mt->nodes[2 * i].hash, mt->hash_size);                         //put hash of left child
            memcpy(buffer + mt->hash_size, mt->nodes[2 * i + 1].hash, mt->hash_size);     //put hash of right child
            
            if (!mt->nodes[i].hash)              //if current node is not hashed still then call hash function to generate hash of it
                mt->nodes[i].hash = (char *)malloc(sizeof(char) * mt->hash_size);
            mt->hash_function(buffer, 2 * mt->hash_size, mt->nodes[i].hash);
            free(buffer);
        }
        else if (2 * i <= mt->n && mt->nodes[2 * i].hash) {                                 //if the node has only left child 
            if (!mt->nodes[i].hash)                                                         //and it is not hashed 
                mt->nodes[i].hash = (char *)malloc(sizeof(char) * mt->hash_size);
            memcpy(mt->nodes[i].hash, mt->nodes[2 * i].hash, mt->hash_size);             //then copy hash of left child to it
        }
    } else {                                                                             //if it is a leaf node
        if (mt->nodes[i].data) {
            if (!mt->nodes[i].hash)                                                     //and it is not hashed
                mt->nodes[i].hash = (char *)malloc(sizeof(char) * mt->hash_size);
            mt->hash_function(mt->nodes[i].data, mt->data_block_size, mt->nodes[i].hash); //then hash it
        }
        else
            return -1;
    }
    return 0;
}


//this function will print the merkle tree
static void print_tree(merkle_tree *mt) {
    
    printf("*******************************\n");
    size_t data_height = mt->h; //Height of the tree
    
    for (size_t level = 0; level < data_height; level++) {     //iterate through number of levels
        size_t first_index = pow(2, level) - 1;;              //index of the first node at this level
        size_t last_index = pow(2, level + 1) - 2;            //index of the last node at this level
        
        printf("Level %zu: ", level);
        for (size_t i = first_index; i <= last_index && i <= mt->n; i++) {    //iterate through each node of the level
            if (mt->nodes[i].hash) {                                        //print hashes of the node 
                MD5Print(mt->nodes[i].hash);
            }
        }
        printf("\n");
    }
    printf("*******************************\n");
}


//this is a function to print the original data
void print_org_data(char **original_data, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("Transaction %zu: %s \t", i + 1, original_data[i]);
    }
}

//this is a function to print the tampered data
void print_tamper_data(char **tamper_data, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("Transaction %zu: %s \t", i + 1, tamper_data[i]);
    }
}



//this is the main function
int main() {
    int n;                                                         //number of transactions
    char **org_data, **tamp_data;

    //First we will take input of number of transaction
    printf("Enter the number of transactions : ");
    scanf("%d", &n);
    getchar();                               //to clear newline character from buffer

    size_t height = (size_t)ceil(log2(n)) + 1; //height of merkle tree is log2(n) + 1 where n is number of transactions

    //now we will initialize merkle tree
    merkle_tree TREE_1 = {0, height, MD5_DIGEST_LENGTH, BLOCK_SIZE, 0, MD5One, NULL};
    merkle_tree TREE_2 = {0, height, MD5_DIGEST_LENGTH, BLOCK_SIZE, 0, MD5One, NULL};


    //memory allocation
    org_data = (char **)malloc(sizeof(char *) * n);
    tamp_data = (char **)malloc(sizeof(char *) * n);


    //now we will take input of transactions
    printf("Enter %d transactions (Format: Sender,Receiver,Amount):\n", n);
    for (int i = 0; i < n; i++) {
        printf("Transaction %d: ", i + 1);
        org_data[i] = (char *)malloc(sizeof(char) * BLOCK_SIZE);  // Allocate memory for each transaction
        scanf(" %[^\n]", org_data[i]);                           // Read the entire line up to a newline character
    }

    //now we will build merkle tree using transactions and then print it
    TREE_1.data_blocks = n;
    make_tree(&TREE_1, org_data);                        //calling funtion make_tree
    printf("\nMerkle Tree after initial transactions:\n");     
    print_tree(&TREE_1);                                       //calling funtion print_tree


    //now we will take tampered transaction
    int tampered_block;
    printf("\nEnter the transaction number to tamper with (1-%d): ", n);
    scanf("%d", &tampered_block);
    getchar();  

    printf("Enter the tampered transaction (Format: Sender,Receiver,Amount): ");
    tamp_data[tampered_block - 1] = (char *)malloc(sizeof(char) * BLOCK_SIZE);
    scanf(" %1023[^\n]", tamp_data[tampered_block - 1]);  


    //rest blocks will have the same data as original data so we will copy them
    for (int i = 0; i < n; i++) {
        if (i != tampered_block - 1) {
            tamp_data[i] = (char *)malloc(sizeof(char) * BLOCK_SIZE);
            memcpy(tamp_data[i], org_data[i], BLOCK_SIZE);
        }
    }


    //now we will build and print tampered merkle tree
    TREE_2.data_blocks = n;
    make_tree(&TREE_2, tamp_data);
    printf("\nMerkle Tree after transaction is tampered :\n");
    print_tree(&TREE_2);


    //now we will compare two merkle trees and check for tempering
    int tampered_transaction = comp_tree(&TREE_1, &TREE_2, 1);
    if (tampered_transaction == 0) {
        printf("\nNo tampering detected.\n");
    } else {
        printf("\nTampering detected in Transaction %d!\n", tampered_transaction);
    }


    //now we will print merkle root of both merkle trees and see the difference if there is any tampering
    printf("\nMerkle Root of Original Tree: ");
    MD5Print(TREE_1.nodes[1].hash);
    printf("Merkle Root of Tampered Tree: ");
    MD5Print(TREE_2.nodes[1].hash);


    //now we will print original and tampered data
    printf("\nOriginal Data:\n");
    print_org_data(org_data, n);
    printf("\nTampered Data:\n");
    print_tamper_data(tamp_data, n);


    //now we will free up the space occupied by both merkle trees and data
    free_Tree_space(&TREE_1);
    free_Tree_space(&TREE_2);
    for (int i = 0; i < n; i++) {
        free(org_data[i]);
        free(tamp_data[i]);
    }
    free(org_data);
    free(tamp_data);

    return 0;
}

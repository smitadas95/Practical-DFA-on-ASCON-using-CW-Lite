#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#define NUM_REGISTERS 5
#define NUM_REGISTERSkey 2
#define NUM_COLUMNS 64


const uint8_t SBOX[32] = {
    0x4,  0xB,  0x1F, 0x14, 0x1A, 0x15, 0x9,  0x2,  
    0x1B, 0x5,  0x8,  0x12, 0x1D, 0x3,  0x6,  0x1C, 
    0x1E, 0x13, 0x7,  0xE,  0x0,  0xD,  0x11, 0x18, 
    0x10, 0xC,  0x1,  0x19, 0x16, 0xA,  0xF,  0x17
};


void apply_sbox_layer(uint64_t state[NUM_REGISTERS]) {
    uint64_t new_state[NUM_REGISTERS] = {0};  

    for (int bit_pos = 0; bit_pos < NUM_COLUMNS; bit_pos++) {

        uint8_t column_value = ((state[4] >> bit_pos) & 1) |
                               (((state[3] >> bit_pos) & 1) << 1) |
                               (((state[2] >> bit_pos) & 1) << 2) |
                               (((state[1] >> bit_pos) & 1) << 3) |
                               (((state[0] >> bit_pos) & 1) << 4);


        uint8_t new_column_value = SBOX[column_value];
        printf("new_column_value is %d , %d\n",column_value, new_column_value);


        for (int reg = 0; reg < NUM_REGISTERS; reg++) {
            new_state[reg] |= ((uint64_t)((new_column_value >> (4-reg)) & 1) << bit_pos);
        }
    }


    for (int i = 0; i < NUM_REGISTERS; i++) {
        state[i] = new_state[i];
       
    }
    
     printf("State after S-box: ");
    for (int i = 0; i < NUM_REGISTERS; i++) {
        printf("0x%016lx ", new_state[i]);
        }
}


const uint8_t invSBOX[32] = {
    0x14, 0x1A, 0x07, 0x0D, 0x00, 0x09, 0x0E, 0x12,
    0x0A, 0x06, 0x1D, 0x01, 0x19, 0x15, 0x13, 0x1E,
    0x18, 0x16, 0x0B, 0x11, 0x03, 0x05, 0x1C, 0x1F,
    0x17, 0x1B, 0x04, 0x08, 0x0F, 0x0C, 0x10, 0x02
};


uint8_t INV_SBOX[32];

void compute_inverse_sbox() {
    for (int i = 0; i < 32; i++) {
        INV_SBOX[invSBOX[i]] = i;
    }
}


void apply_inverse_sbox(uint64_t state[NUM_REGISTERS]) {
    uint64_t new_state[NUM_REGISTERS] = {0};  

    for (int bit_pos = 0; bit_pos < NUM_COLUMNS; bit_pos++) {

        uint8_t column_value = ((state[4] >> bit_pos) & 1) |
                               (((state[3] >> bit_pos) & 1) << 1) |
                               (((state[2] >> bit_pos) & 1) << 2) |
                               (((state[1] >> bit_pos) & 1) << 3) |
                               (((state[0] >> bit_pos) & 1) << 4);


        uint8_t new_column_value = invSBOX[column_value];


        for (int reg = 0; reg < NUM_REGISTERS; reg++) {
            new_state[reg] |= ((uint64_t)((new_column_value >> (4-reg)) & 1) << bit_pos);
        }
    }


    for (int i = 0; i < NUM_REGISTERS; i++) {
        state[i] = new_state[i];
    }
}


void hex_to_registers(const char *hex, uint64_t state[NUM_REGISTERS]) {
    for (int i = 0; i < NUM_REGISTERS; i++) {
        sscanf(hex + (i * 16), "%16lx", &state[i]);
    }
}



void hex_to_registers_forKey(const char *hex, uint64_t state[NUM_REGISTERSkey]) {
    for (int i = 0; i < NUM_REGISTERSkey; i++) {
        sscanf(hex + (i * 16), "%16lx", &state[i]);
    }
}


void print_state_bin(uint64_t state[NUM_REGISTERS]) {
    for (int i = 0; i < NUM_REGISTERS; i++) {
        for(int j = 63; j >= 0; j--) {
            printf("%c", (state[i] & (1ULL << j)) ? '1' : '0');
        }
        printf(" ");  // Separate 64-bit words each
    }
    printf("\n");
}

// Function to print a hex string as binary
void print_hex_as_binary(const unsigned char *hex) {
 int bit_count = 0;
 int x[320];
    while (*hex) {
        unsigned int byte;
        sscanf((const char *)hex, "%2x", &byte);  // Read two hex chars as a byte
        for (int i = 7; i >= 0; i--) {            // Print each bit (MSB to LSB)
            printf("%c", (byte & (1 << i)) ? '1' : '0');
            printf(" ");
            
        }
       
        bit_count+=8;
        
        printf("  ");
    
    if (bit_count % 64 == 0){
    
            printf("reg %d",x[bit_count%64]);
            
    
    printf("\n");
    }
    hex+=2;
    }
    if (bit_count % 64 != 0){
    printf("\n");
    }
    printf("\n");

}


int main() {
    compute_inverse_sbox();


    unsigned char ciphertext[] =    "a8f74bcff763d7cee943af8af55c4a3087b78747d265d6c1cd57cb074997542cf5e84325a5183822";
    unsigned char faulty_cipher[] = "a8f74bcff56fd72de943af8ac15e480987b78747646bd03acd57cb07ff9952d7f5e84325a5183822";
    unsigned char key[] = "00000000000000000000000000000000";
    
        printf("Original Tag is %s \n",ciphertext);
        printf("Faulty Tag is   %s \n",faulty_cipher);
        
	printf("Tag xor_diff\n\n");
	
    for(int i=0; i<80 ; i++){
    
    	printf("%4d", ciphertext[i]^faulty_cipher[i]);
    	
    	//printf("%c", ciphertext[i]);
    	if ((i+1)%16 == 0){
    		printf("\n");
    		}
    		
    }
    
    
    uint64_t cipher_state[NUM_REGISTERS], fcipher_state1[NUM_REGISTERS], dummy[NUM_REGISTERS], keyxor[NUM_REGISTERSkey];
   
    
    hex_to_registers(ciphertext, cipher_state);
    hex_to_registers(faulty_cipher, fcipher_state1);
    hex_to_registers_forKey(key, keyxor);
    
    printf("Glitch Test4:\n");
    printf("Correct Tag:\t%lx %lx %lx %lx %lx\n", cipher_state[0], cipher_state[1], cipher_state[2], cipher_state[3], cipher_state[4]);
    // printf("Faulty Tag:\t%lx %lx %lx %lx %lx\n", fcipher_state1[0], fcipher_state1[1], fcipher_state1[2], fcipher_state1[3], fcipher_state1[4]);
    printf("Faulty Tag:\t%016lx %016lx %016lx %016lx %016lx\n", 
    fcipher_state1[0], fcipher_state1[1], fcipher_state1[2], fcipher_state1[3], fcipher_state1[4]);

    

    dummy[0] = cipher_state[0]^fcipher_state1[0];
    dummy[1] = cipher_state[1]^fcipher_state1[1];
    dummy[2] = cipher_state[2]^fcipher_state1[2];
    dummy[3] = cipher_state[3]^fcipher_state1[3];
    dummy[4] = cipher_state[4]^fcipher_state1[4];
    
    printf("The Final State difference:\n");
    for(int i = 63; i >=0; i--) {
    	
    	printf("%ld ", ((dummy[0]>>i) & 0x1));
    }
    printf("\n");
    
    for(int i = 63; i >=0; i--) {
    	
    	printf("%ld ", ((dummy[1]>>i) & 0x1));
    	
    	
    }
    printf("\n");
    
    for(int i = 63; i >=0; i--) {
    	
    	printf("%ld ", ((dummy[2]>>i) & 0x1));
    }
    printf("\n");
    
    for(int i = 63; i >=0; i--) {
    	
    	printf("%ld ", ((dummy[3]>>i) & 0x1));
    }
    printf("\n");
    
    for(int i = 63; i >=0; i--) {
    	
    	printf("%ld ", ((dummy[4]>>i) & 0x1));
    }
    printf("\n\n");
    
    // Last State xor with key0, key1 wrt x3, x4
    
    cipher_state[3] ^= keyxor[0];
    cipher_state[4] ^= keyxor[1];
    fcipher_state1[3] ^= keyxor[0];
    fcipher_state1[4] ^= keyxor[1];
    
    // Apply the inverse ct of ori. ct
    apply_inverse_sbox(cipher_state);
    
    
    // Apply the inverse ct of f. ct
    apply_inverse_sbox(fcipher_state1);
     
    
    // Output
    uint64_t odummy[NUM_REGISTERS];
    
   
    
    odummy[0] = cipher_state[0]^fcipher_state1[0];
    odummy[1] = cipher_state[1]^fcipher_state1[1];
    odummy[2] = cipher_state[2]^fcipher_state1[2];
    odummy[3] = cipher_state[3]^fcipher_state1[3];
    odummy[4] = cipher_state[4]^fcipher_state1[4];
    
    printf("The state difference(final) by applying the Inverse S-box:\n");
    
    for(int i = 63; i >=0; i--) {
    	
    	printf("%ld ", ((odummy[0]>>i) & 0x1));
    }
    printf("\n");
    
    for(int i = 63; i >=0; i--) {
    	
    	printf("%ld ", ((odummy[1]>>i) & 0x1));
    	
    	
    }
    printf("\n");
    
    for(int i = 63; i >=0; i--) {
    	
    	printf("%ld ", ((odummy[2]>>i) & 0x1));
    }
    printf("\n");
    
    for(int i = 63; i >=0; i--) {
    	
    	printf("%ld ", ((odummy[3]>>i) & 0x1));
    }
    printf("\n");
    
    for(int i = 63; i >=0; i--) {
    	
    	printf("%ld ", ((odummy[4]>>i) & 0x1));
    }
    printf("\n\n\n");

    return 0;
    
}


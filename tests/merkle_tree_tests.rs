use merkle_tree::binary_merkle_tree::{BinaryMerkleTree, Blake3Hasher, CHUNK_LEN, IV, FLAGS, ChunkState};
use rand::Rng;
use std::time::Instant;
use std::collections::HashMap;

// Test configuration constants
const RAW_BYTES_SIZE: usize = 16777216; // 16MB = 2 ** 24 bytes
const FUZZ_BYTES_SIZE: usize = 4096; // 4KB for faster fuzz testing
const FUZZ_ITERATIONS: usize = 1000;
const BULK_MUTATIONS: [usize; 6] = [5, 10, 50, 100, 500, 1000]; // Different numbers of mutations to test

/// Tests the initial hash value computation of BinaryMerkleTree
/// Verifies that the root hash matches the BLAKE3 hash of the input
/// Methods tested: BinaryMerkleTree::new_from_leaves, BinaryMerkleTree::root
#[test]
fn test_initial_hash_value_match() {
    // Generate random input
    let mut rng = rand::thread_rng();
    let input: Vec<u8> = (0..RAW_BYTES_SIZE).map(|_| rng.gen()).collect();
    
    // Get initial BLAKE3 hash
    let mut hasher = Blake3Hasher::new();
    hasher.update(&input);
    let mut initial_hash = [0; 32];
    hasher.finalize(&mut initial_hash);
    
    // Convert initial hash bytes to chaining value format (8 u32 values)
    let mut initial_blake3_chaining_value = [0u32; 8];
    for i in 0..8 {
        initial_blake3_chaining_value[i] = u32::from_le_bytes(initial_hash[i*4..(i+1)*4].try_into().unwrap());
    }
    
    // Process through Merkle tree
    let tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
    let initial_root = tree.root().chaining_value();
    
    // Assert that the initial root matches the BLAKE3 hash
    assert_eq!(initial_root, initial_blake3_chaining_value, 
        "Initial root hash {:?} does not match BLAKE3 hash {:?}", 
        initial_root, initial_blake3_chaining_value);
}

/// Tests single mutation handling in BinaryMerkleTree
/// Verifies that updating a single leaf node correctly propagates changes to the root
/// Methods tested: BinaryMerkleTree::insert_leaf, BinaryMerkleTree::root
#[test]
fn test_single_mutation_hash_value_match() {
    // Generate random input
    let mut rng = rand::thread_rng();
    let mut input: Vec<u8> = (0..RAW_BYTES_SIZE).map(|_| rng.gen()).collect();
    
    // Process through Merkle tree initially
    let mut tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
    
    // Select 1 position to mutate
    let mutation_index = rng.gen_range(0..input.len());
    let original_byte = input[mutation_index];
    input[mutation_index] = original_byte ^ 0xFF; // Flip all bits

    // Find which chunk contains our mutated byte
    let chunk_index = mutation_index / CHUNK_LEN;

    // Create new Output for the mutated chunk
    let mut chunk_state = ChunkState::new(IV, chunk_index as u64, FLAGS);
    let chunk_start = chunk_index * CHUNK_LEN;
    let chunk_end = std::cmp::min(chunk_start + CHUNK_LEN, input.len());
    chunk_state.update(&input[chunk_start..chunk_end]);
    let mutated_chunk_output = chunk_state.output();

    // Time the tree update operation
    let update_start = Instant::now();
    tree.insert_leaf(chunk_index, mutated_chunk_output);
    let mutated_root = tree.root().chaining_value();
    let update_duration = update_start.elapsed();
    println!("Tree root computation in updated merkle tree took: {:?}", update_duration);

    // Time the BLAKE3 hash computation
    let blake3_start = Instant::now();
    let mut hasher = Blake3Hasher::new();
    hasher.update(&input);
    let mut mutated_hash = [0; 32];
    hasher.finalize(&mut mutated_hash);
    let blake3_duration = blake3_start.elapsed();
    println!("BLAKE3 hash computation took: {:?}", blake3_duration);
    
    // Convert mutated hash bytes to chaining value format
    let mut mutated_blake3_chaining_value = [0u32; 8];
    for i in 0..8 {
        mutated_blake3_chaining_value[i] = u32::from_le_bytes(mutated_hash[i*4..(i+1)*4].try_into().unwrap());
    }

    // Assert that the mutated root matches the mutated BLAKE3 hash
    assert_eq!(mutated_root, mutated_blake3_chaining_value,
        "Mutated root hash {:?} does not match mutated BLAKE3 hash {:?}",
        mutated_root, mutated_blake3_chaining_value);
}

/// Fuzz tests single mutation handling with random inputs
/// Tests BinaryMerkleTree's ability to handle random mutations across different positions
/// Methods tested: BinaryMerkleTree::insert_leaf, BinaryMerkleTree::root
#[test]
fn test_fuzz_single_mutation() {
    let mut rng = rand::thread_rng();
    
    for iteration in 0..FUZZ_ITERATIONS {
        // Generate random input for this iteration
        let mut input: Vec<u8> = (0..FUZZ_BYTES_SIZE).map(|_| rng.gen()).collect();
        
        // Process through Merkle tree initially
        let mut tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
        
        // Select 1 position to mutate
        let mutation_index = rng.gen_range(0..input.len());
        let original_byte = input[mutation_index];
        input[mutation_index] = original_byte ^ 0xFF; // Flip all bits

        // Find which chunk contains our mutated byte
        let chunk_index = mutation_index / CHUNK_LEN;

        // Create new Output for the mutated chunk
        let mut chunk_state = ChunkState::new(IV, chunk_index as u64, FLAGS);
        let chunk_start = chunk_index * CHUNK_LEN;
        let chunk_end = std::cmp::min(chunk_start + CHUNK_LEN, input.len());
        chunk_state.update(&input[chunk_start..chunk_end]);
        let mutated_chunk_output = chunk_state.output();

        // Update merkle tree and get new root
        tree.insert_leaf(chunk_index, mutated_chunk_output);
        let mutated_root = tree.root().chaining_value();

        // Compute full BLAKE3 hash for comparison
        let mut hasher = Blake3Hasher::new();
        hasher.update(&input);
        let mut mutated_hash = [0; 32];
        hasher.finalize(&mut mutated_hash);
        
        // Convert hash to chaining value format
        let mut mutated_blake3_chaining_value = [0u32; 8];
        for i in 0..8 {
            mutated_blake3_chaining_value[i] = u32::from_le_bytes(mutated_hash[i*4..(i+1)*4].try_into().unwrap());
        }

        // Assert equality and print diagnostic info on failure
        assert_eq!(mutated_root, mutated_blake3_chaining_value,
            "Iteration {}: Mutation at index {} (chunk {}) failed.\nRoot hash: {:?}\nBLAKE3 hash: {:?}",
            iteration, mutation_index, chunk_index, mutated_root, mutated_blake3_chaining_value);
    }
    println!("Successfully completed {} fuzz test iterations for single mutation", FUZZ_ITERATIONS);
}

/// Tests bulk mutation handling in BinaryMerkleTree
/// Verifies that updating multiple leaf nodes efficiently propagates changes to the root
/// Methods tested: BinaryMerkleTree::bulk_insert_leaves, BinaryMerkleTree::root
#[test]
fn test_bulk_mutations() {
    let mut rng = rand::thread_rng();
    
    for &num_mutations in BULK_MUTATIONS.iter() {
        println!("\nTesting with {} random mutations:", num_mutations);
        
        // Generate initial random input
        let mut input: Vec<u8> = (0..RAW_BYTES_SIZE).map(|_| rng.gen()).collect();
        
        // Process through Merkle tree initially
        let mut tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
        
        // Generate sorted random mutation positions
        let mut mutation_positions: Vec<usize> = (0..input.len()).collect();
        let mut selected_positions = Vec::with_capacity(num_mutations);
        for _ in 0..num_mutations {
            let pos = rng.gen_range(0..mutation_positions.len());
            selected_positions.push(mutation_positions.remove(pos));
        }
        selected_positions.sort(); // Must be sorted for bulk_insert_leaves
        
        // Track chunks that need updating
        let mut chunk_updates: HashMap<usize, Vec<usize>> = HashMap::new();
        
        // First pass: Apply all mutations and group by chunk. 
        // It is possible that the same chunk is mutated multiple times.
        for &pos in &selected_positions {
            // Mutate the byte
            let original_byte = input[pos];
            input[pos] = original_byte ^ 0xFF;
            
            // Group mutations by chunk
            let chunk_index = pos / CHUNK_LEN;
            chunk_updates.entry(chunk_index)
                .or_insert_with(Vec::new)
                .push(pos);
        }
        
        // Convert chunk_updates into sorted vectors
        let mut sorted_chunk_indices: Vec<_> = chunk_updates.keys().cloned().collect();
        sorted_chunk_indices.sort(); // Ensure chunk indices are sorted
        
        // Second pass: Process each chunk exactly once in sorted order
        let mut chunk_indices = Vec::with_capacity(chunk_updates.len());
        let mut chunk_outputs = Vec::with_capacity(chunk_updates.len());
        
        for &chunk_index in &sorted_chunk_indices {
            let chunk_start = chunk_index * CHUNK_LEN;
            let chunk_end = std::cmp::min(chunk_start + CHUNK_LEN, input.len());
            
            // Calculate chunk output after all mutations in this chunk
            let mut chunk_state = ChunkState::new(IV, chunk_index as u64, FLAGS);
            chunk_state.update(&input[chunk_start..chunk_end]);
            
            chunk_indices.push(chunk_index);
            chunk_outputs.push(chunk_state.output());
        }
        
        // Time the Merkle tree bulk update
        let merkle_start = Instant::now();
        tree.bulk_insert_leaves(chunk_indices.into_iter(), chunk_outputs.into_iter());
        let mutated_root = tree.root().chaining_value();
        let merkle_duration = merkle_start.elapsed();
        println!("Merkle tree bulk update + root computation took: {:?}", merkle_duration);
        
        // Time the BLAKE3 hash computation
        let blake3_start = Instant::now();
        let mut hasher = Blake3Hasher::new();
        hasher.update(&input);
        let mut mutated_hash = [0; 32];
        hasher.finalize(&mut mutated_hash);
        let blake3_duration = blake3_start.elapsed();
        println!("BLAKE3 hash computation took: {:?}", blake3_duration);
        println!("Merkle tree is {:.2}x faster than BLAKE3", 
                 blake3_duration.as_nanos() as f64 / merkle_duration.as_nanos() as f64);
        
        // Convert hash to chaining value format and verify
        let mut mutated_blake3_chaining_value = [0u32; 8];
        for i in 0..8 {
            mutated_blake3_chaining_value[i] = u32::from_le_bytes(mutated_hash[i*4..(i+1)*4].try_into().unwrap());
        }
        
        assert_eq!(mutated_root, mutated_blake3_chaining_value,
            "Bulk mutation test failed with {} mutations.\nRoot hash: {:?}\nBLAKE3 hash: {:?}",
            num_mutations, mutated_root, mutated_blake3_chaining_value);
    }
}

/// Fuzz tests bulk mutation handling with random inputs
/// Tests BinaryMerkleTree's ability to handle random bulk mutations across different positions
/// Methods tested: BinaryMerkleTree::bulk_insert_leaves, BinaryMerkleTree::root
#[test]
fn test_fuzz_bulk_mutations() {
    let mut rng = rand::thread_rng();
    
    for iteration in 0..FUZZ_ITERATIONS {
        // Generate random input for this iteration
        let mut input: Vec<u8> = (0..FUZZ_BYTES_SIZE).map(|_| rng.gen()).collect();
        
        // Process through Merkle tree initially
        let mut tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
        
        // Choose a random number of mutations between 1 and 1000 for each iteration
        let num_mutations = rng.gen_range(1..=1000);
        
        // Generate sorted random mutation positions
        let mut mutation_positions: Vec<usize> = (0..input.len()).collect();
        let mut selected_positions = Vec::with_capacity(num_mutations);
        for _ in 0..num_mutations {
            let pos = rng.gen_range(0..mutation_positions.len());
            selected_positions.push(mutation_positions.remove(pos));
        }
        selected_positions.sort();
        
        // Track chunks that need updating
        let mut chunk_updates: HashMap<usize, Vec<usize>> = HashMap::new();
        
        // First pass: Apply all mutations and group by chunk
        for &pos in &selected_positions {
            let original_byte = input[pos];
            input[pos] = original_byte ^ 0xFF;
            
            let chunk_index = pos / CHUNK_LEN;
            chunk_updates.entry(chunk_index)
                .or_insert_with(Vec::new)
                .push(pos);
        }
        
        // Convert chunk_updates into sorted vectors
        let mut sorted_chunk_indices: Vec<_> = chunk_updates.keys().cloned().collect();
        sorted_chunk_indices.sort();
        
        // Second pass: Process each chunk exactly once in sorted order
        let mut chunk_indices = Vec::with_capacity(chunk_updates.len());
        let mut chunk_outputs = Vec::with_capacity(chunk_updates.len());
        
        for &chunk_index in &sorted_chunk_indices {
            let chunk_start = chunk_index * CHUNK_LEN;
            let chunk_end = std::cmp::min(chunk_start + CHUNK_LEN, input.len());
            
            let mut chunk_state = ChunkState::new(IV, chunk_index as u64, FLAGS);
            chunk_state.update(&input[chunk_start..chunk_end]);
            
            chunk_indices.push(chunk_index);
            chunk_outputs.push(chunk_state.output());
        }
        
        // Update merkle tree with bulk mutations
        tree.bulk_insert_leaves(chunk_indices.into_iter(), chunk_outputs.into_iter());
        let mutated_root = tree.root().chaining_value();
        
        // Compute full BLAKE3 hash for comparison
        let mut hasher = Blake3Hasher::new();
        hasher.update(&input);
        let mut mutated_hash = [0; 32];
        hasher.finalize(&mut mutated_hash);
        
        // Convert hash to chaining value format
        let mut mutated_blake3_chaining_value = [0u32; 8];
        for i in 0..8 {
            mutated_blake3_chaining_value[i] = u32::from_le_bytes(mutated_hash[i*4..(i+1)*4].try_into().unwrap());
        }
        
        // Assert equality and print diagnostic info on failure
        assert_eq!(mutated_root, mutated_blake3_chaining_value,
            "Iteration {}: Bulk mutation with {} mutations failed.\nMutation positions: {:?}\nAffected chunks: {:?}\nRoot hash: {:?}\nBLAKE3 hash: {:?}",
            iteration, num_mutations, selected_positions, sorted_chunk_indices, mutated_root, mutated_blake3_chaining_value);
        
        if iteration > 0 && iteration % 100 == 0 {
            println!("Completed {} fuzz iterations for bulk mutations", iteration);
        }
    }
    println!("Successfully completed {} fuzz test iterations with random bulk mutations", FUZZ_ITERATIONS);
}
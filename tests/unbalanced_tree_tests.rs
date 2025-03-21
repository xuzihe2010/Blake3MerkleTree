use merkle_tree::binary_merkle_tree::{BinaryMerkleTree, Blake3Hasher, CHUNK_LEN, IV, FLAGS, ChunkState};
use rand::Rng;
use std::collections::HashMap;

const BYTES_SIZE_LOW_BOUND: usize = 10000; 
const BYTES_SIZE_HIGH_BOUND: usize = 100000; 
const RANDOM_MUTATION_LOW_BOUND: usize = 10;
const RANDOM_MUTATION_HIGH_BOUND: usize = 500;
const FUZZ_BYTES_SIZE_LOW_BOUND: usize = 1000; 
const FUZZ_BYTES_SIZE_HIGH_BOUND: usize = 10000;
const FUZZ_ITERATIONS: usize = 1000;

#[test]
fn test_unbalanced_tree_creation() {
    // Create input data that will produce these chaining values
    let mut input = Vec::new();
    for i in 1..=3 {
        let mut chunk_state = ChunkState::new(IV, (i-1) as u64, 0);
        let chunk_data = vec![i as u8; CHUNK_LEN];
        chunk_state.update(&chunk_data);
        input.extend_from_slice(&chunk_data);
    }

    // Create tree with 3 leaves (not a power of 2)
    let tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
    assert_eq!(tree.actual_leaves(), 3);
    
    // Get BLAKE3 hash of the entire input
    let mut hasher = Blake3Hasher::new();
    hasher.update(&input);
    let mut hash = [0; 32];
    hasher.finalize(&mut hash);
    
    // Convert hash to chaining value format
    let mut blake3_chaining_value = [0u32; 8];
    for i in 0..8 {
        blake3_chaining_value[i] = u32::from_le_bytes(hash[i*4..(i+1)*4].try_into().unwrap());
    }
    
    // Compare root chaining value with BLAKE3 hash
    let root = tree.root();
    assert_eq!(root.chaining_value(), blake3_chaining_value,
        "Root chaining value {:?} does not match BLAKE3 hash {:?}",
        root.chaining_value(), blake3_chaining_value);
}

#[test]
fn test_unbalanced_tree_insert() {
    println!("\n=== Starting unbalanced tree insert test ===\n");
    
    // Generate random input with size between lower and upper bound bytes
    let mut rng = rand::thread_rng();
    let input_size = rng.gen_range(BYTES_SIZE_LOW_BOUND..=BYTES_SIZE_HIGH_BOUND);
    let mut input: Vec<u8> = (0..input_size).map(|_| rng.gen()).collect();
    
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
    println!("BLAKE3 final root chaining value: {:?}", initial_blake3_chaining_value);
    
    // Process through UnbalancedMerkleTree initially
    let mut tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
    let initial_root = tree.root().chaining_value();
    
    println!("\nInitial hash values:");
    println!("BLAKE3 chaining value: {:?}", initial_blake3_chaining_value);
    println!("Merkle tree root:      {:?}", initial_root);
    
    assert_eq!(initial_root, initial_blake3_chaining_value,
        "Initial hash mismatch for input size {} bytes", input_size);
    println!("Initial hash values match ✓");
    
    // Select a random chunk to mutate
    let num_chunks = (input_size + CHUNK_LEN - 1) / CHUNK_LEN;
    let chunk_index = rng.gen_range(0..num_chunks);
    println!("\nMutation details:");
    println!("Input size: {} bytes", input_size);
    println!("Number of chunks: {}", num_chunks);
    println!("Selected chunk index: {} of {}", chunk_index, num_chunks);
    println!("Chunk range: {} to {} (size: {} bytes)", 
             chunk_index * CHUNK_LEN,
             std::cmp::min((chunk_index + 1) * CHUNK_LEN, input.len()),
             std::cmp::min(CHUNK_LEN, input.len() - chunk_index * CHUNK_LEN));
    
    // Mutate the selected chunk in the input
    let chunk_start = chunk_index * CHUNK_LEN;
    let chunk_end = std::cmp::min(chunk_start + CHUNK_LEN, input.len());
    for i in chunk_start..chunk_end {
        input[i] = input[i] ^ 0xFF; // Flip all bits in the chunk
    }
    
    // Create new chunk state for the mutated chunk
    let mut chunk_state = ChunkState::new(IV, chunk_index as u64, FLAGS);
    chunk_state.update(&input[chunk_start..chunk_end]);
    let mutated_chunk_output = chunk_state.output();
    
    // Update tree with mutated chunk
    tree.insert_leaf(chunk_index, mutated_chunk_output);
    let mutated_root = tree.root().chaining_value();
    
    // Get mutated BLAKE3 hash
    let mut hasher = Blake3Hasher::new();
    hasher.update(&input);
    let mut mutated_hash = [0; 32];
    hasher.finalize(&mut mutated_hash);
    
    // Convert hash to chaining value format and verify
    let mut mutated_blake3_chaining_value = [0u32; 8];
    for i in 0..8 {
        mutated_blake3_chaining_value[i] = u32::from_le_bytes(mutated_hash[i*4..(i+1)*4].try_into().unwrap());
    }
    
    // Verify mutated hash values match
    assert_eq!(mutated_root, mutated_blake3_chaining_value,
        "Mutated hash mismatch for input size {} bytes", input_size);
    println!("Mutated hash values match ✓");
    println!("\n=== Test completed successfully ===");
}

#[test]
fn test_fuzz_unbalanced_tree_insert() {
    println!("\n=== Starting fuzz test for unbalanced tree insert ===\n");
    let num_iterations = FUZZ_ITERATIONS;
    let mut rng = rand::thread_rng();
    
    for iteration in 0..num_iterations {
        // Generate random input with size between low and high bound bytes
        let input_size = rng.gen_range(FUZZ_BYTES_SIZE_LOW_BOUND..=FUZZ_BYTES_SIZE_HIGH_BOUND);
        let mut input: Vec<u8> = (0..input_size).map(|_| rng.gen()).collect();
        
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
        
        // Process through UnbalancedMerkleTree initially
        let mut tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
        let initial_root = tree.root().chaining_value();
        
        assert_eq!(initial_root, initial_blake3_chaining_value,
            "Initial hash mismatch in iteration {} for input size {} bytes", iteration + 1, input_size);
        
        // Select a random chunk to mutate
        let num_chunks = (input_size + CHUNK_LEN - 1) / CHUNK_LEN;
        let chunk_index = rng.gen_range(0..num_chunks);
        
        // Mutate the selected chunk in the input
        let chunk_start = chunk_index * CHUNK_LEN;
        let chunk_end = std::cmp::min(chunk_start + CHUNK_LEN, input.len());
        for i in chunk_start..chunk_end {
            input[i] = input[i] ^ 0xFF; // Flip all bits in the chunk
        }
        
        // Create new chunk state for the mutated chunk
        let mut chunk_state = ChunkState::new(IV, chunk_index as u64, FLAGS);
        chunk_state.update(&input[chunk_start..chunk_end]);
        let mutated_chunk_output = chunk_state.output();
        
        // Update tree with mutated chunk
        tree.insert_leaf(chunk_index, mutated_chunk_output);
        let mutated_root = tree.root().chaining_value();

        
        // Get mutated BLAKE3 hash
        let mut hasher = Blake3Hasher::new();
        hasher.update(&input);
        let mut mutated_hash = [0; 32];
        hasher.finalize(&mut mutated_hash);
        
        // Convert hash to chaining value format and verify
        let mut mutated_blake3_chaining_value = [0u32; 8];
        for i in 0..8 {
            mutated_blake3_chaining_value[i] = u32::from_le_bytes(mutated_hash[i*4..(i+1)*4].try_into().unwrap());
        }
        
        assert_eq!(mutated_root, mutated_blake3_chaining_value,
            "Mutated hash mismatch in iteration {} for input size {} bytes", iteration + 1, input_size);
    }
    
    println!("\n=== Fuzz test completed successfully - {} iterations passed ===", num_iterations);
}

#[test]
fn test_unbalanced_tree_bulk_insert() {
    println!("\n=== Starting unbalanced tree bulk insert test ===\n");
    
    // Generate random input with size between lower and upper bound bytes
    let mut rng = rand::thread_rng();
    let input_size = rng.gen_range(BYTES_SIZE_LOW_BOUND..=BYTES_SIZE_HIGH_BOUND);
    let mut input: Vec<u8> = (0..input_size).map(|_| rng.gen()).collect();
    
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
    println!("BLAKE3 final root chaining value: {:?}", initial_blake3_chaining_value);
    
    // Process through UnbalancedMerkleTree initially
    let mut tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
    let initial_root = tree.root().chaining_value();
    
    println!("\nInitial hash values:");
    println!("BLAKE3 chaining value: {:?}", initial_blake3_chaining_value);
    println!("Merkle tree root:      {:?}", initial_root);
    
    assert_eq!(initial_root, initial_blake3_chaining_value,
        "Initial hash mismatch for input size {} bytes", input_size);
    println!("Initial hash values match ✓");

    // Generate random number of mutations between 10 and 50
    let num_mutations = rng.gen_range(RANDOM_MUTATION_LOW_BOUND..=RANDOM_MUTATION_HIGH_BOUND);
    println!("\nMutation details:");
    println!("Input size: {} bytes", input_size);
    println!("Number of mutations: {}", num_mutations);
    
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
    
    // First pass: Apply all mutations and group by chunk
    for &pos in &selected_positions {
        // Mutate the byte
        let original_byte = input[pos];
        input[pos] = original_byte ^ 0xFF; // Flip all bits
        
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
    
    // Update tree with bulk mutations
    tree.bulk_insert_leaves(chunk_indices.into_iter(), chunk_outputs.into_iter())
        .expect("Bulk insert failed");
    let mutated_root = tree.root().chaining_value();
    
    // Get mutated BLAKE3 hash
    let mut hasher = Blake3Hasher::new();
    hasher.update(&input);
    let mut mutated_hash = [0; 32];
    hasher.finalize(&mut mutated_hash);
    
    // Convert hash to chaining value format
    let mut mutated_blake3_chaining_value = [0u32; 8];
    for i in 0..8 {
        mutated_blake3_chaining_value[i] = u32::from_le_bytes(mutated_hash[i*4..(i+1)*4].try_into().unwrap());
    }
    
    // Verify all hash values match
    assert_eq!(mutated_root, mutated_blake3_chaining_value,
        "Bulk mutated hash mismatch for input size {} bytes", input_size);
    println!("Bulk mutation hash values match ✓");
    println!("\n=== Test completed successfully ===");
}

#[test]
fn test_fuzz_unbalanced_tree_bulk_insert() {
    println!("\n=== Starting fuzz test for unbalanced tree bulk insert ===\n");
    let num_iterations = FUZZ_ITERATIONS;
    let mut rng = rand::thread_rng();
    
    for iteration in 0..num_iterations {
        // Generate random input with size between low and high bound bytes
        let input_size = rng.gen_range(FUZZ_BYTES_SIZE_LOW_BOUND..=FUZZ_BYTES_SIZE_HIGH_BOUND);
        let mut input: Vec<u8> = (0..input_size).map(|_| rng.gen()).collect();
        
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
        
        // Process through UnbalancedMerkleTree initially
        let mut tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
        let initial_root = tree.root().chaining_value();
        
        assert_eq!(initial_root, initial_blake3_chaining_value,
            "Initial hash mismatch in iteration {} for input size {} bytes", iteration + 1, input_size);
        
        // Generate random number of mutations between 10 and 50
        let num_mutations = rng.gen_range(RANDOM_MUTATION_LOW_BOUND..=RANDOM_MUTATION_HIGH_BOUND);
        
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
        
        // First pass: Apply all mutations and group by chunk
        for &pos in &selected_positions {
            // Mutate the byte
            let original_byte = input[pos];
            input[pos] = original_byte ^ 0xFF; // Flip all bits
            
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
        
        // Update tree with bulk mutations
        tree.bulk_insert_leaves(chunk_indices.into_iter(), chunk_outputs.into_iter())
            .expect("Bulk insert failed");
        let mutated_root = tree.root().chaining_value();
        
        // Get mutated BLAKE3 hash
        let mut hasher = Blake3Hasher::new();
        hasher.update(&input);
        let mut mutated_hash = [0; 32];
        hasher.finalize(&mut mutated_hash);
        
        // Convert hash to chaining value format
        let mut mutated_blake3_chaining_value = [0u32; 8];
        for i in 0..8 {
            mutated_blake3_chaining_value[i] = u32::from_le_bytes(mutated_hash[i*4..(i+1)*4].try_into().unwrap());
        }
        
        // Verify all hash values match
        assert_eq!(mutated_root, mutated_blake3_chaining_value,
            "Bulk mutated hash mismatch in iteration {} for input size {} bytes", iteration + 1, input_size);
    }
    
    println!("\n=== Fuzz test completed successfully - {} iterations passed ===", num_iterations);
}

#[test]
fn test_unbalanced_tree_corner_cases() {
    println!("\n=== Starting unbalanced tree corner cases test ===\n");
    
    // Test Case 1: Empty input
    println!("\nTest Case 1: Empty input");
    let input: Vec<u8> = Vec::new();
    let tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
    let root = tree.root().chaining_value();
    
    // Get BLAKE3 hash of empty input
    let mut hasher = Blake3Hasher::new();
    hasher.update(&input);
    let mut hash = [0; 32];
    hasher.finalize(&mut hash);
    
    let mut blake3_chaining_value = [0u32; 8];
    for i in 0..8 {
        blake3_chaining_value[i] = u32::from_le_bytes(hash[i*4..(i+1)*4].try_into().unwrap());
    }
    
    assert_eq!(root, blake3_chaining_value, "Empty input hash mismatch");
    println!("Empty input test passed ✓");

    // Test Case 2: Very short input (less than one chunk)
    println!("\nTest Case 2: Very short input (100 bytes)");
    let input: Vec<u8> = (0..100).map(|i| i as u8).collect();
    let tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
    let initial_root = tree.root().chaining_value();
    
    // Get BLAKE3 hash
    let mut hasher = Blake3Hasher::new();
    hasher.update(&input);
    let mut hash = [0; 32];
    hasher.finalize(&mut hash);
    
    let mut blake3_chaining_value = [0u32; 8];
    for i in 0..8 {
        blake3_chaining_value[i] = u32::from_le_bytes(hash[i*4..(i+1)*4].try_into().unwrap());
    }
    
    assert_eq!(initial_root, blake3_chaining_value, "Very short input hash mismatch");
    println!("Very short input test passed ✓");

    // Test Case 3: Exact chunk size input (1024 bytes)
    println!("\nTest Case 3: Exact chunk size input (1024 bytes)");
    let input: Vec<u8> = (0..CHUNK_LEN).map(|i| i as u8).collect();
    let tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
    let initial_root = tree.root().chaining_value();
    
    // Get BLAKE3 hash
    let mut hasher = Blake3Hasher::new();
    hasher.update(&input);
    let mut hash = [0; 32];
    hasher.finalize(&mut hash);
    
    let mut blake3_chaining_value = [0u32; 8];
    for i in 0..8 {
        blake3_chaining_value[i] = u32::from_le_bytes(hash[i*4..(i+1)*4].try_into().unwrap());
    }
    
    assert_eq!(initial_root, blake3_chaining_value, "Exact chunk size input hash mismatch");
    println!("Exact chunk size input test passed ✓");

    // Test Case 4: Multiple exact chunks (3 * 1024 bytes)
    println!("\nTest Case 4: Multiple exact chunks (3 * 1024 bytes)");
    let input: Vec<u8> = (0..3 * CHUNK_LEN).map(|i| i as u8).collect();
    let mut tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
    let initial_root = tree.root().chaining_value();
    
    // Get BLAKE3 hash
    let mut hasher = Blake3Hasher::new();
    hasher.update(&input);
    let mut hash = [0; 32];
    hasher.finalize(&mut hash);
    
    let mut blake3_chaining_value = [0u32; 8];
    for i in 0..8 {
        blake3_chaining_value[i] = u32::from_le_bytes(hash[i*4..(i+1)*4].try_into().unwrap());
    }
    
    assert_eq!(initial_root, blake3_chaining_value, "Multiple exact chunks hash mismatch");
    println!("Multiple exact chunks test passed ✓");

    // Test Case 5: Mutate first and last bytes of chunks
    println!("\nTest Case 5: Mutate first and last bytes of chunks");
    let mut input: Vec<u8> = (0..3 * CHUNK_LEN).map(|i| i as u8).collect();
    
    // Track chunks that need updating
    let mut chunk_updates: HashMap<usize, Vec<usize>> = HashMap::new();
    
    // Mutate first and last bytes of each chunk
    for chunk_index in 0..3 {
        let chunk_start = chunk_index * CHUNK_LEN;
        let chunk_end = chunk_start + CHUNK_LEN;
        
        // Mutate first byte
        input[chunk_start] ^= 0xFF;
        chunk_updates.entry(chunk_index)
            .or_insert_with(Vec::new)
            .push(chunk_start);
        
        // Mutate last byte
        input[chunk_end - 1] ^= 0xFF;
        chunk_updates.entry(chunk_index)
            .or_insert_with(Vec::new)
            .push(chunk_end - 1);
    }
    
    // Convert chunk_updates into sorted vectors
    let mut sorted_chunk_indices: Vec<_> = chunk_updates.keys().cloned().collect();
    sorted_chunk_indices.sort();
    
    // Process each chunk exactly once in sorted order
    let mut chunk_indices = Vec::with_capacity(chunk_updates.len());
    let mut chunk_outputs = Vec::with_capacity(chunk_updates.len());
    
    for &chunk_index in &sorted_chunk_indices {
        let chunk_start = chunk_index * CHUNK_LEN;
        let chunk_end = chunk_start + CHUNK_LEN;
        
        // Calculate chunk output after all mutations in this chunk
        let mut chunk_state = ChunkState::new(IV, chunk_index as u64, FLAGS);
        chunk_state.update(&input[chunk_start..chunk_end]);
        
        chunk_indices.push(chunk_index);
        chunk_outputs.push(chunk_state.output());
    }
    
    // Update tree with bulk mutations
    tree.bulk_insert_leaves(chunk_indices.into_iter(), chunk_outputs.into_iter())
        .expect("Bulk insert failed");
    let mutated_root = tree.root().chaining_value();
    
    // Get mutated BLAKE3 hash
    let mut hasher = Blake3Hasher::new();
    hasher.update(&input);
    let mut mutated_hash = [0; 32];
    hasher.finalize(&mut mutated_hash);
    
    let mut mutated_blake3_chaining_value = [0u32; 8];
    for i in 0..8 {
        mutated_blake3_chaining_value[i] = u32::from_le_bytes(mutated_hash[i*4..(i+1)*4].try_into().unwrap());
    }
    
    assert_eq!(mutated_root, mutated_blake3_chaining_value,
        "First/last byte mutation hash mismatch");
    println!("First/last byte mutation test passed ✓");

    println!("\n=== All corner cases tests completed successfully ===");
} 
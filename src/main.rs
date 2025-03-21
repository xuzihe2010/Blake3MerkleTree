mod binary_merkle_tree;

use rand::Rng;
use std::time::Instant;
use std::collections::HashMap;
use crate::binary_merkle_tree::{BinaryMerkleTree, ChunkState, Blake3Hasher, CHUNK_LEN, IV, FLAGS};

const INPUT_SIZE: usize = 10000000; // ~10MB
const MUTATION_COUNTS: [usize; 8] = [5, 10, 50, 100, 500, 1000, 5000, 10000]; // Different numbers of mutations to test

fn main() {
    println!("Benchmarking Merkle Tree vs BLAKE3 with increasing mutations ({} bytes input):", INPUT_SIZE);
    println!("----------------------------------------------------------------");
    println!("| Mutations | Merkle Time | BLAKE3 Time | Speed Ratio |");
    println!("----------------------------------------------------------------");

    let mut rng = rand::thread_rng();
    
    for &num_mutations in MUTATION_COUNTS.iter() {
        // Generate initial random input
        let mut input: Vec<u8> = (0..INPUT_SIZE).map(|_| rng.gen()).collect();
        
        // Process through Merkle tree initially
        let mut tree = BinaryMerkleTree::from_input(&input, IV, FLAGS);
        
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
            
            let mut chunk_state = ChunkState::new(IV, chunk_index as u64, 0);
            chunk_state.update(&input[chunk_start..chunk_end]);
            
            chunk_indices.push(chunk_index);
            chunk_outputs.push(chunk_state.output());
        }
        
        // Time the Merkle tree bulk update
        let merkle_start = Instant::now();
        tree.bulk_insert_leaves(chunk_indices.into_iter(), chunk_outputs.into_iter());
        let mutated_root = tree.root().chaining_value();
        let merkle_duration = merkle_start.elapsed();
        
        // Time the BLAKE3 hash computation
        let blake3_start = Instant::now();
        let mut hasher = Blake3Hasher::new();
        hasher.update(&input);
        let mut mutated_hash = [0; 32];
        hasher.finalize(&mut mutated_hash);
        let blake3_duration = blake3_start.elapsed();
        
        // Convert hash to chaining value format and verify
        let mut mutated_blake3_chaining_value = [0u32; 8];
        for i in 0..8 {
            mutated_blake3_chaining_value[i] = u32::from_le_bytes(mutated_hash[i*4..(i+1)*4].try_into().unwrap());
        }
        
        // Calculate and print performance metrics
        let speed_ratio = blake3_duration.as_nanos() as f64 / merkle_duration.as_nanos() as f64;
        println!("| {:9} | {:11.3?} | {:11.3?} | {:10.2}x |", 
                 num_mutations, merkle_duration, blake3_duration, speed_ratio);
        
        // Verify correctness
        assert_eq!(mutated_root, mutated_blake3_chaining_value,
            "Hash mismatch with {} mutations", num_mutations);
    }
    println!("----------------------------------------------------------------");
}
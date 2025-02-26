//! Ring arithmetic operations for ML-KEM and ML-DSA.
//! 
//! This module implements arithmetic in the finite field ℤq
//! used by both ML-KEM and ML-DSA, including efficient Montgomery 
//! arithmetic for modular operations.

/// Field element in ℤq with operations implemented using Montgomery arithmetic
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement {
    /// Value in Montgomery representation
    value: u32,
    /// The modulus
    modulus: u32,
    /// Montgomery constant R^2 mod q
    r2: u32,
    /// Montgomery constant -q^(-1) mod 2^32
    qinv: u32,
}

/// Montgomery arithmetic implementation for efficient modular operations
pub struct Montgomery {
    /// The modulus
    modulus: u32,
    /// Montgomery constant R^2 mod q
    r2: u32,
    /// Montgomery constant -q^(-1) mod 2^32
    qinv: u32,
}

impl Montgomery {
    /// Create a new Montgomery context for ML-KEM/ML-DSA operations
    pub fn new() -> Self {
        // Constants for q = 8380417
        let modulus = 8380417;
        
        // R^2 mod q where R = 2^32
        let r2 = 58728449;
        
        // -q^(-1) mod 2^32
        let qinv = 4236238847;
        
        Self { modulus, r2, qinv }
    }
    
    /// Convert a regular integer to Montgomery form
    pub fn to_montgomery(&self, value: u32) -> FieldElement {
        let mont_value = self.montgomery_multiply(value, self.r2);
        FieldElement {
            value: mont_value,
            modulus: self.modulus,
            r2: self.r2,
            qinv: self.qinv,
        }
    }
    
    /// Convert from Montgomery form back to a regular integer
    pub fn from_montgomery(&self, element: &FieldElement) -> u32 {
        self.montgomery_multiply(element.value, 1)
    }
    
    /// Perform Montgomery multiplication: (a * b * R^(-1)) mod q
    #[inline(always)]
    pub fn montgomery_multiply(&self, a: u32, b: u32) -> u32 {
        let temp = a as u64 * b as u64;
        let m = ((temp as u32).wrapping_mul(self.qinv)) as u64;
        let t = (temp.wrapping_add(m * self.modulus as u64)) >> 32;
        
        if t >= self.modulus as u64 {
            (t - self.modulus as u64) as u32
        } else {
            t as u32
        }
    }
}

impl FieldElement {
    /// Create a new field element from a value
    pub fn new(value: u32, context: &Montgomery) -> Self {
        context.to_montgomery(value)
    }
    
    /// Get the value in non-Montgomery form
    pub fn value(&self, context: &Montgomery) -> u32 {
        context.from_montgomery(self)
    }
    
    /// Add another field element
    pub fn add(&self, other: &Self) -> Self {
        let mut result = *self;
        
        result.value = result.value.wrapping_add(other.value);
        if result.value >= self.modulus {
            result.value -= self.modulus;
        }
        
        result
    }
    
    /// Subtract another field element
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = *self;
        
        if result.value < other.value {
            result.value = result.value.wrapping_add(self.modulus);
        }
        result.value = result.value.wrapping_sub(other.value);
        
        result
    }
    
    /// Multiply by another field element
    pub fn mul(&self, other: &Self, context: &Montgomery) -> Self {
        let mut result = *self;
        
        result.value = context.montgomery_multiply(self.value, other.value);
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_montgomery_conversion() {
        let context = Montgomery::new();
        
        for i in 0..100 {
            let value = i * 1000;
            let mont = context.to_montgomery(value);
            let back = context.from_montgomery(&mont);
            
            assert_eq!(value, back);
        }
    }
    
    #[test]
    fn test_field_arithmetic() {
        let context = Montgomery::new();
        
        let a = FieldElement::new(1234, &context);
        let b = FieldElement::new(5678, &context);
        
        // Test addition
        let c = a.add(&b);
        assert_eq!(c.value(&context), (1234 + 5678) % context.modulus);
        
        // Test subtraction
        let d = a.sub(&b);
        let expected = if 1234 < 5678 {
            1234 + context.modulus - 5678
        } else {
            1234 - 5678
        };
        assert_eq!(d.value(&context), expected % context.modulus);
        
        // Test multiplication
        let e = a.mul(&b, &context);
        assert_eq!(e.value(&context), (1234 * 5678) % context.modulus);
    }
}
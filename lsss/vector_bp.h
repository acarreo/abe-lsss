#ifndef __VECTOR_BP_H__
#define __VECTOR_BP_H__

#include <vector>
#include "zelement_bp.h"

typedef enum ElementType {
  VECTOR_G1_ELEMENT = 0xF1,
  VECTOR_G2_ELEMENT = 0xF2,
} ElementType;

typedef enum CompressionType {
  BIN_UNCOMPRESSED = 0x00,
  BIN_COMPRESSED = 0x01,
} CompressionType;


typedef struct {
  uint8_t dim;
  g1_t *elements;
} g1_vector_t, *g1_vector_ptr;

typedef struct {
  uint8_t dim;
  g2_t *elements;
} g2_vector_t, *g2_vector_ptr;


class OpenABEByteString;

class G1_Vector : public std::vector<G1> {
private:
  size_t dim;
  bool isDimSet;

public:
  G1_Vector() : std::vector<G1>(), isDimSet(false) {}
  G1_Vector(size_t dim) : std::vector<G1>(dim), dim(dim), isDimSet(true) {}
  G1_Vector(std::initializer_list<G1> init_list) : std::vector<G1>(init_list), isDimSet(false) {}
  G1_Vector(const G1_Vector &other) : std::vector<G1>(other), dim(other.dim), isDimSet(other.isDimSet) {}
  G1_Vector(const g1_vector_ptr &g1_vector);

  ~G1_Vector() { this->clear(); this->dim = 0; this->isDimSet = false; }

  void setDim(size_t dim) {
    if (!this->isDimSet) {
      this->resize(dim); this->dim = dim; this->isDimSet = true;
    }
  }

  size_t getDim() const { return this->isDimSet ? this->dim : this->size(); }

  size_t getSizeInBytes(CompressionType compress) const;

  g1_vector_ptr getG1Vector() const;

  bool isFixedSize() const { return this->isDimSet; }

  void addElement(const G1 &element);
  void insertElement(const G1 &element, size_t index);

  void serialize(OpenABEByteString &result, CompressionType compress) const;
  void deserialize(OpenABEByteString &input);

  bool operator==(const G1_Vector &x) const;
  G1_Vector& operator=(const G1_Vector &other);
  G1_Vector  operator+(const G1_Vector &other) const;
  G1_Vector  operator*(const ZP &k) const;

  // Temporary methods for testing, will be removed later
  void random(size_t dim) {
    G1_Vector vect(dim);
    for (size_t i = 0; i < dim; i++) {
      G1 g1; g1.setRandom();
      vect.insertElement(g1, i);
    }
    *this = vect;
  }

};
  

class G2_Vector : public std::vector<G2> {
private:
  size_t dim;
  bool isDimSet;

public:
  G2_Vector() : std::vector<G2>() {}
  G2_Vector(size_t dim) : std::vector<G2>(dim), dim(dim), isDimSet(true) {}
  G2_Vector(std::initializer_list<G2> init_list) : std::vector<G2>(init_list), isDimSet(false) {}
  G2_Vector(const G2_Vector &other) : std::vector<G2>(other), dim(other.dim), isDimSet(other.isDimSet) {}
  G2_Vector(const g2_vector_ptr &g2_vector);

  ~G2_Vector() {
    this->clear(); this->dim = 0; this->isDimSet = false;
  }

  void setDim(size_t dim) {
    if (!this->isDimSet) {
      this->resize(dim); this->dim = dim; this->isDimSet = true;
    }
  }

  size_t getDim() const {
    return this->isDimSet ? this->dim : this->size();
  }

  size_t getSizeInBytes(CompressionType compress) const;

  g2_vector_ptr getG2Vector() const;

  bool isFixedSize() const { return this->isDimSet; }

  void addElement(const G2 &element);
  void insertElement(const G2 &element, size_t index);

  void serialize(OpenABEByteString &result, CompressionType compress) const;
  void deserialize(OpenABEByteString &input);

  bool operator==(const G2_Vector &x) const;
  G2_Vector& operator=(const G2_Vector &other);
  G2_Vector  operator+(const G2_Vector &other) const;
  G2_Vector  operator*(const ZP &k) const;

  // Temporary methods for testing, will be removed later
  void random(size_t dim) {
    G2 g2;
    G2_Vector vect;
    for (size_t i = 0; i < dim; i++) {
      g2.setRandom();
      vect.push_back(g2);
    }
    vect.setDim(dim);
    *this = vect;
  }

};


// Inner product of two vectors
GT innerProduct(const G1_Vector &x, const G2_Vector &y);

void clear_g1_vector(g1_vector_ptr &g1_vector);
void clear_g2_vector(g2_vector_ptr &g2_vector);


#endif // __VECTOR_BP_H__

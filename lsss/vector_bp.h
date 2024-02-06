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

class OpenABEByteString;

class G1_Vector : public std::vector<G1> {
private:
  size_t dim;
  bool isDimSet;

public:
  G1_Vector() : std::vector<G1>() {}
  G1_Vector(size_t dim) : std::vector<G1>(dim), dim(dim), isDimSet(true) {}
  G1_Vector(std::initializer_list<G1> init_list) : std::vector<G1>(init_list) {}

  void setDim(size_t dim) {
    if (!this->isDimSet) {
      this->resize(dim); this->dim = dim; this->isDimSet = true;
    }
  }

  size_t getDim() const {
    return this->isDimSet ? this->dim : this->size();
  }

  bool isFixedSize() const {
    return this->isDimSet;
  }

  void addElement(const G1 &element);
  void insertElement(const G1 &element, size_t index);

  // remove element at index and clear the vector must be revised
  void removeElement(size_t index) {
    if (index < this->size()) {
      this->erase(this->begin() + index);
    }
  }
  void clear() {
    std::vector<G1>::clear();
  }

  size_t getSizeInBytes(CompressionType compress) const;

  void serialize(OpenABEByteString &result, CompressionType compress) const;
  void deserialize(OpenABEByteString &input);

  // define operator==
  bool operator==(const G1_Vector &x) const;

  // Temporary methods for testing, will be removed later
  void random(size_t dim) {
    G1 g1;
    this->clear();
    for (size_t i = 0; i < dim; i++) {
      g1.setRandom();
      this->push_back(g1);
    }
    this->setDim(dim);
  }

};
  










#endif // __VECTOR_BP_H__

#ifndef __VECTOR_BP_H__
#define __VECTOR_BP_H__

#include <vector>
#include <zlsss.h>

typedef enum ElementType {
  VECTOR_G1_ELEMENT = 0xF1,
  VECTOR_G2_ELEMENT = 0xF2,
} ElementType;


class OpenABEByteString;

class G1_Vector : public std::vector<G1> {
public:
  G1_Vector() : std::vector<G1>() {}
  G1_Vector(size_t dim) : std::vector<G1>(dim) {}
  G1_Vector(std::initializer_list<G1> init_list) : std::vector<G1>(init_list) {}

  void addElement(const G1 &element) {
    this->push_back(element);
  }

  void insertElement(const G1 &element, size_t index) {
    if (index <= this->size()) {
      this->at(index) = element;
    }
  }

  void removeElement(size_t index) {
    if (index < this->size()) {
      this->erase(this->begin() + index);
    }
  }

  void clear() {
    std::vector<G1>::clear();
  }

  void serialize(OpenABEByteString &result) const;
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
  }

};
  










#endif // __VECTOR_BP_H__

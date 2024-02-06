#include "vector_bp.h"


void G1_Vector::serialize(OpenABEByteString &result, CompressionType compress) const {
  OpenABEByteString temp;
  uint8_t dim = this->getDim();

  size_t index = 0, g1_size = 0;
  g1_size = (compress == BIN_COMPRESSED ? G1_SIZE_BIN_COMPRESSED : G1_SIZE_BIN);
  temp.fillBuffer(0, g1_size * dim);
  for (size_t i = 0; i < dim; i++) {
    g1_write_bin(temp.getInternalPtr() + index, g1_size, this->at(i).m_G1, compress);
    index += g1_size;
  }

  result.clear();
  result.insertFirstByte(VECTOR_G1_ELEMENT);
  result.pack8bits(dim);
  result.pack8bits(compress);
  result.smartPack(temp);
}

void G1_Vector::deserialize(OpenABEByteString &input) {
  OpenABEByteString temp;
  size_t index = 0, g1_size = 0;
  uint8_t element_type = input.at(index); index++;
  if (element_type == VECTOR_G1_ELEMENT) {
    uint8_t dim = input.at(index); index++;

    uint8_t compress = input.at(index); index++;
    g1_size = (compress == BIN_COMPRESSED ? G1_SIZE_BIN_COMPRESSED : G1_SIZE_BIN);

    temp = input.smartUnpack(&index);

    G1 g1;
    this->clear();
    size_t pos = 0;
    uint8_t *temp_buffer = temp.getInternalPtr();
    for (size_t i = 0; i < (size_t)dim; i++) {
      g1_read_bin(g1.m_G1, temp_buffer + pos, g1_size);
      this->push_back(g1);
      pos += g1_size;
    }
    this->setDim(dim);
  }
}

bool G1_Vector::operator==(const G1_Vector &x) const {
  if (this->size() != x.size()) {
    return false;
  }

  for (size_t i = 0; i < this->size(); i++) {
    if (!(this->at(i) == x.at(i))) {
      return false;
    }
  }

  return true;
}
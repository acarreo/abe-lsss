#include "vector_bp.h"


/****************************************************************************/
/*                                G1_Vector                                 */
/****************************************************************************/

void G1_Vector::addElement(const G1 & element) {
  if (this->isDimSet && this->size() < this->dim) {
    this->push_back(element);
  }
  else if (!this->isDimSet) {
    this->push_back(element);
  }
  else {
    throw std::runtime_error("Cannot add more elements to the vector");
  }
}

void G1_Vector::insertElement(const G1 & element, size_t index) {
  if (this->isDimSet && index < this->dim) {
    this->at(index) = element;
  }
  else if (index < this->size()) {
    this->at(index) = element;
  }
  else {
    throw std::runtime_error("Cannot insert more elements to the vector");
  }
}

size_t G1_Vector::getSizeInBytes(CompressionType compress) const {
  size_t buff_size = 0, total_size = 0;

  if (this->size() == 0) return 0;

  // size of G1_Vector in bytes
  buff_size = (compress == BIN_COMPRESSED ? G1_SIZE_BIN_COMPRESSED : G1_SIZE_BIN);
  buff_size *= this->getDim();

  // ADD : type of vector group, size of dim and compression type
  total_size = 3 * sizeof(uint8_t);

  // ADD : size of G1_Vector in bytes
  total_size += sizeof(uint8_t) +
                ((buff_size > UINT16_MAX) ? sizeof(uint32_t) :
                ((buff_size > UINT16_MAX) ? sizeof(uint16_t) : sizeof(uint8_t)));

  total_size += buff_size; // ADD : buff_size

  // For some reason that I don't know, we need to add 1 to total_size
  return total_size + 1;
}

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

G1_Vector & G1_Vector::operator=(const G1_Vector &other) {
  this->clear();
  for (size_t i = 0; i < other.size(); i++) {
    this->push_back(other.at(i));
  }
  this->setDim(other.getDim());
  return *this;
}

G1_Vector G1_Vector::operator+(const G1_Vector &other) const {
  if (this->getDim() != other.getDim()) {
    throw std::runtime_error("Cannot add two vectors with different dimensions");
  }

  G1_Vector result(this->getDim());
  for (size_t i = 0; i < this->getDim(); i++) {
    result.insertElement(this->at(i) + other.at(i), i);
  }
  return result;
}

G1_Vector G1_Vector::operator*(const ZP &k) const {
  G1_Vector result(this->getDim());
  for (size_t i = 0; i < this->getDim(); i++) {
    result.insertElement(this->at(i) * k, i);
  }
  return result;
}


/****************************************************************************/
/*                                G2_Vector                                 */
/****************************************************************************/

void G2_Vector::addElement(const G2 & element) {
  if (this->isDimSet && this->size() < this->dim) {
    this->push_back(element);
  }
  else if (!this->isDimSet) {
    this->push_back(element);
  }
  else {
    throw std::runtime_error("Cannot add more elements to the vector");
  }
}

void G2_Vector::insertElement(const G2 & element, size_t index) {
  if (this->isDimSet && index < this->dim) {
    this->at(index) = element;
  }
  else if (index < this->size()) {
    this->at(index) = element;
  }
  else {
    throw std::runtime_error("Cannot insert more elements to the vector");
  }
}

size_t G2_Vector::getSizeInBytes(CompressionType compress) const {
  size_t buff_size = 0, total_size = 0;

  if (this->size() == 0) return 0;

  // size of G2_Vector in bytes
  buff_size = (compress == BIN_COMPRESSED ? G2_SIZE_BIN_COMPRESSED : G2_SIZE_BIN);
  buff_size *= this->getDim();

  // ADD : type of vector group, size of dim and compression type
  total_size = 3 * sizeof(uint8_t);

  // ADD : size of G2_Vector in bytes
  total_size += sizeof(uint8_t) +
                ((buff_size > UINT16_MAX) ? sizeof(uint32_t) :
                ((buff_size > UINT16_MAX) ? sizeof(uint16_t) : sizeof(uint8_t)));

  total_size += buff_size; // ADD : buff_size

  // For some reason that I don't know, we need to add 1 to total_size
  return total_size + 1;
}

void G2_Vector::serialize(OpenABEByteString &result, CompressionType compress) const {
  OpenABEByteString temp;
  uint8_t dim = this->getDim();

  size_t index = 0, g2_size = 0;
  g2_size = (compress == BIN_COMPRESSED ? G2_SIZE_BIN_COMPRESSED : G2_SIZE_BIN);
  temp.fillBuffer(0, g2_size * dim);
  for (size_t i = 0; i < dim; i++) {
    g2_write_bin(temp.getInternalPtr() + index, g2_size, this->at(i).m_G2, compress);
    index += g2_size;
  }

  result.clear();
  result.insertFirstByte(VECTOR_G2_ELEMENT);
  result.pack8bits(dim);
  result.pack8bits(compress);
  result.smartPack(temp);
}

void G2_Vector::deserialize(OpenABEByteString &input) {
  OpenABEByteString temp;
  size_t index = 0, g2_size = 0;
  uint8_t element_type = input.at(index); index++;
  if (element_type == VECTOR_G2_ELEMENT) {
    uint8_t dim = input.at(index); index++;

    uint8_t compress = input.at(index); index++;
    g2_size = (compress == BIN_COMPRESSED ? G2_SIZE_BIN_COMPRESSED : G2_SIZE_BIN);

    temp = input.smartUnpack(&index);

    G2 g2;
    this->clear();
    size_t pos = 0;
    uint8_t *temp_buffer = temp.getInternalPtr();
    for (size_t i = 0; i < (size_t)dim; i++) {
      g2_read_bin(g2.m_G2, temp_buffer + pos, g2_size);
      this->push_back(g2);
      pos += g2_size;
    }
    this->setDim(dim);
  }
}

bool G2_Vector::operator==(const G2_Vector &x) const {
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

G2_Vector & G2_Vector::operator=(const G2_Vector &other) {
  this->clear();
  for (size_t i = 0; i < other.size(); i++) {
    this->push_back(other.at(i));
  }
  this->setDim(other.getDim());
  return *this;
}

G2_Vector G2_Vector::operator+(const G2_Vector &other) const {
  if (this->getDim() != other.getDim()) {
    throw std::runtime_error("Cannot add two vectors with different dimensions");
  }

  G2_Vector result(this->getDim());
  for (size_t i = 0; i < this->getDim(); i++) {
    result.insertElement(this->at(i) + other.at(i), i);
  }
  return result;
}

G2_Vector G2_Vector::operator*(const ZP &k) const {
  G2_Vector result(this->getDim());
  for (size_t i = 0; i < this->getDim(); i++) {
    result.insertElement(this->at(i) * k, i);
  }
  return result;
}

// interned string table
// Copyright (C) 2015 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "config.h"
#include "stringtable.h"
#include "unordered.h"

#include <string>
#include <cstring>


using namespace std;
using namespace boost;

#if INTERNED_STRING_CUSTOM_HASH
// A custom hash 
struct stringtable_hash
{
  size_t operator()(const string& c) const {
    const char* b = c.data();
    size_t real_length = c.size();
    const size_t blocksize = 64; // a cache line or two

    // hash the length
    size_t hash = real_length;

    // hash the beginning
    size_t length = real_length;
    if (length > blocksize)
      length = blocksize;
    while (length-- > 0)
      hash = (hash * 131) + *b++;

    // hash the last byte
    hash = (hash * 131) + *(c.data() + real_length - 1);
    
    // XXX: hash the middle / end too?
    
    return hash;
  }
};
typedef unordered_set<std::string, stringtable_hash> stringtable_t;
#else
typedef unordered_set<std::string> stringtable_t;
#endif


stringtable_t stringtable;


// Generate a long-lived string_ref for the given input string.  In
// the absence of proper refcounting, memory is kept for the whole
// duration of the systemtap run.  Try to reuse the same string
// object for multiple invocations.  Old string_refs remain valid 
// because std::set<> guarantees iterator validity across inserts,
// which means that our value strings stay put.

interned_string interned_string::intern(const string& value)
{
  stringtable_t::iterator it = (stringtable.insert(value)).first; // persistent iterator!
  return interned_string (string_ref (it->data(), it->length())); // hope for RVO/elision

  // XXX: for future consideration, consider searching the stringtable
  // for instances where 'value' is a substring.  We could string_ref
  // to substrings just fine.  The trouble is that searching the
  // stringtable naively is very timetaking; it saves memory but costs
  // mucho CPU.
}


interned_string::interned_string(const char* value): string_ref(intern(value)), _c_str(0)
{
}
                                                                
interned_string::interned_string(const string& value): string_ref(intern(value)), _c_str(0)
{
}

interned_string& interned_string::operator = (const std::string& value)
{
  *this = intern(value);
  return *this;
}

interned_string& interned_string::operator = (const char* value)
{
  *this = intern(value);
  return *this;
}

#if INTERNED_STRING_FIND_MEMMEM
size_t interned_string::find (const boost::string_ref& f) const
{
  const char *ptr = (const char*) memmem (this->data(), this->size(),
                                          f.data(), f.size());
  if (ptr)
    return (ptr - this->data());
  else
    return boost::string_ref::npos;
}

size_t interned_string::find (const std::string& f) const
{
  const char *ptr = (const char*) memmem (this->data(), this->size(),
                                          f.data(), f.size());
  if (ptr)
    return (ptr - this->data());
  else
    return boost::string_ref::npos;
}

size_t interned_string::find (const char *f) const
{
  const char *ptr = (const char*) memmem (this->data(), this->size(),
                                          f, strlen(f));
  if (ptr)
    return (ptr - this->data());
  else
    return boost::string_ref::npos;
}
#endif

// The result of c_str() is basically strdup()'d, in anticipation
// that interning may result in string_refs that are not followed by \0,
// so we can't just pass back ->data().  The strdup()'d memory is
// saved in a member variable and freed in the destructor.
const char* interned_string::c_str() const
{
  free (_c_str);
  _c_str = (char*) malloc(this->length()+1);
  strncpy(_c_str, this->data(), this->length());
  _c_str[this->length()]='\0';
  return _c_str;
}

/* vim: set sw=2 ts=8 cino=>4,n-2,{2,^-2,t0,(0,u0,w1,M1 : */

package com.example.signalnine;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.security.auth.Subject;
import java.io.Serializable;
import java.security.Principal;

@NoArgsConstructor
@AllArgsConstructor
@Data
class SignalUser implements Principal, Serializable {
    Long id;
    String username;

    @Override
    public String getName() {
        return username;
    }

    @Override   // asks: is this a lowest-level User Principal ?
    public boolean implies(Subject subject) {
        return true;
    }
}

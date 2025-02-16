package com.github.Dhanesh.dto.response;

import com.github.Dhanesh.model.RoleType;
import lombok.Data;

/**
 * Data Transfer Object for Role response
 */
@Data
public class RoleResponse {

    private Long id;
    private RoleType type;
}

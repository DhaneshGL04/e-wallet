package com.github.Dhanesh.validator;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import static com.github.Dhanesh.common.Constants.*;

/**
 * Used for validating IBAN numbers
 */
@Slf4j(topic = "IbanValidator")
@RequiredArgsConstructor
@Component
public class IbanValidator implements ConstraintValidator<ValidIban, String> {

    @Override
    public boolean isValid(String iban, ConstraintValidatorContext context) {
        // Check if the IBAN is null or empty
        if (iban == null || iban.trim().isEmpty()) {
            return false;
        }

        // Trim leading and trailing whitespace
        String trimmed = iban.trim();

        // Check if the length is within the valid range
        if (trimmed.length() < IBAN_MIN_SIZE || trimmed.length() > IBAN_MAX_SIZE) {
            return false;
        }

        // Basic constraint: ensure the input consists of only alphanumeric characters
        for (char c : trimmed.toCharArray()) {
            if (!Character.isLetterOrDigit(c)) {
                return false;
            }
        }

        // If all checks pass, consider it valid
        return true;
    }
}
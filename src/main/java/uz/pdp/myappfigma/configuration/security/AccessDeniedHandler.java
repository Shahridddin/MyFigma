package uz.pdp.myappfigma.configuration.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import uz.pdp.myappfigma.dto.BaseResponse;
import uz.pdp.myappfigma.dto.ErrorData;

import java.io.IOException;

@Component
public class AccessDeniedHandler implements org.springframework.security.web.access.AccessDeniedHandler {

    private final ObjectMapper jacksonObjectMapper;
    private static final Logger logger = LoggerFactory.getLogger(AccessDeniedHandler.class);

    public AccessDeniedHandler(ObjectMapper jacksonObjectMapper) {
        this.jacksonObjectMapper = jacksonObjectMapper;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        logger.error("access denied", e);
        response.setHeader("Content-Type", "application/json");
        response.setStatus(403);
        ServletOutputStream outputStream = response.getOutputStream();
        ErrorData error = new ErrorData("access denied");
        BaseResponse<Void> responseBody = new BaseResponse<>(error);
        jacksonObjectMapper.writeValue(outputStream, responseBody);
    }
}

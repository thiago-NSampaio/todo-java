package br.com.thiagonascimento.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.thiagonascimento.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {
    @Autowired
    private IUserRepository userRepository;
 
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
            var serletPath = request.getServletPath();
            if (serletPath.startsWith("/tasks/")) {
            // pegar a autenticação
           var authorization = request.getHeader("Authorization");
           System.out.println("Authorization");

           var authEncoded = authorization.substring("Basic".length()).trim();

           byte[] authDecode = Base64.getDecoder().decode((authEncoded));

           var authString = new String(authDecode);
           String[] credentials = authString.split(":");

           var username = credentials[0];
           var passWord = credentials[1];
            System.out.println(username);
           System.out.println(passWord);
           System.out.println(authDecode);

           // validar usuário
           var user = this.userRepository.findByUsername(username);

           if (user == null) {
            response.sendError(401 );
        } else {
            // validar senha
            var passwordVerify = BCrypt.verifyer().verify(passWord.toCharArray(), user.getPassword());
            if (passwordVerify.verified) {
                request.setAttribute("idUser", user.getId());
                filterChain.doFilter(request, response);
            } else {
                response.sendError(401 );
            }
        }
        // segue enfrente
        }else{
            filterChain.doFilter(request, response);

        }
          
    }
    
}

package com.sansec.common.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2019/2/24 16:55
 */
//@Configuration("swagger")
//@EnableSwagger2
//public class Swagger2 {
//    @Autowired
//    SwaggerInfo swaggerInfo;
//    @Bean
//    public Docket createRestApi() {
//        ParameterBuilder tokenPar = new ParameterBuilder();
//        List<Parameter> pars = new ArrayList<>();
//        tokenPar.name(swaggerInfo.getParameterName())
//                .description(swaggerInfo.getParameterDescription())
//                .modelRef(new ModelRef(swaggerInfo.getParameterType()))
//                .parameterType(swaggerInfo.getType())
//                .required(true)
//                .build();
//        pars.add(tokenPar.build());
//
//        Docket docket = new Docket(DocumentationType.SWAGGER_2)
//                .groupName(swaggerInfo.getGroupName())
//                .apiInfo(apiInfo());
//        ApiSelectorBuilder apiSelectorBuilder = docket.select();
//        if(StringUtils.isNotBlank(swaggerInfo.getBasePackage())){
//            apiSelectorBuilder = apiSelectorBuilder.apis(RequestHandlerSelectors.basePackage(swaggerInfo.getBasePackage()));
//        }
//        if(StringUtils.isNotBlank(swaggerInfo.getAntPath())){
//            apiSelectorBuilder = apiSelectorBuilder.paths(PathSelectors.ant(swaggerInfo.getAntPath()));
//        }
//        return apiSelectorBuilder.build().globalOperationParameters(pars);
//    }
//
//    private ApiInfo apiInfo() {
//        return new ApiInfoBuilder()
//                .title(swaggerInfo.getTitle())
//                .description(swaggerInfo.getDescription())
//                .contact(new Contact(swaggerInfo.getUserName(),null,swaggerInfo.getEmail()))
//                .version(swaggerInfo.getVersion())
//                .build();
//    }
//}
@Configuration
@EnableSwagger2
public class Swagger2 {
    @Autowired
    SwaggerInfo swaggerInfo;
    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2).
                useDefaultResponseMessages(false)
                .select()
                .apis(RequestHandlerSelectors.basePackage(swaggerInfo.getBasePackage()))
                .paths(PathSelectors.regex("^(?!auth).*$"))
                .build()
                .securitySchemes(securitySchemes())
                .securityContexts(securityContexts())
                .apiInfo(apiInfo())
                .groupName(swaggerInfo.getGroupName())
                ;
    }
    private List<ApiKey> securitySchemes() {
        return newArrayList(
                new ApiKey("Authorization", "JWT-Token", "header"));
    }
    private List<SecurityContext> securityContexts() {
        return newArrayList(
                SecurityContext.builder()
                        .securityReferences(defaultAuth())
                        .forPaths(PathSelectors.regex("^(?!auth).*$"))
//                        .forPaths(PathSelectors.regex(DEFAULT_INCLUDE_PATTERN))
                        .build()
        );
    }
    List<SecurityReference> defaultAuth() {
        AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return newArrayList(
                new SecurityReference("Authorization", authorizationScopes));
    }
    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title(swaggerInfo.getTitle())
                .description(swaggerInfo.getDescription())
                .contact(new Contact(swaggerInfo.getUserName(),null,swaggerInfo.getEmail()))
                .version(swaggerInfo.getVersion())
                .build();
    }
}
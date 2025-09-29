/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import {
    CanActivate,
    ExecutionContext,
    HttpException,
    HttpStatus,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtService } from '@nestjs/jwt';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from './roles-auth.decorator';
import { User } from 'src/users/users.model';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(
        private jwtService: JwtService,
        private reflector: Reflector,
    ) {}

    canActivate(
        context: ExecutionContext,
    ): boolean | Promise<boolean> | Observable<boolean> {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(
            ROLES_KEY,
            [context.getHandler(), context.getClass()],
        );
        if (!requiredRoles) {
            return true;
        }
        const req = context.switchToHttp().getRequest();
        try {
            const authHeader = req.headers.authorization;
            const bearer = authHeader.split(' ')[0];
            const token = authHeader.split(' ')[1];

            if (bearer !== 'Bearer' || !token) {
                throw new UnauthorizedException({
                    message: 'Пользователь не авторизован',
                });
            }

            const user: User = this.jwtService.verify(token);
            req.user = user;
            return user.roles.some((role) =>
                requiredRoles.includes(role.value),
            );
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
        } catch (e) {
            throw new HttpException('Нет доступа', HttpStatus.FORBIDDEN);
        }
    }
}

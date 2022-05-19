import {
  ForbiddenException,
  HttpException,
  Injectable,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import { RegisterDto } from './dto/register.dto';
import { Tokens } from './type';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signUp(dto: RegisterDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);
    let newUser;

    try {
      newUser = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError) {
        if (e.code === 'P2002') {
          throw new UnprocessableEntityException(
            'email address is already in use',
          );
        }
      }
      throw e;
    }

    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async signIn(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user)
      throw new NotFoundException(
        'email and password do not match an existing account',
      );

    await this.verifyHash(
      dto.password,
      user.hash,
      new NotFoundException(
        'email and password do not match an existing account',
      ),
    );

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async signOut(userId: number): Promise<boolean> {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
    return true;
  }

  async refreshToken(userId: number, rt: string) {
    console.log(userId);
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user) throw new NotFoundException('user not found');

    await this.verifyHash(
      rt,
      user.hashedRt,
      new ForbiddenException('refresh token is invalid'),
    );

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async hashData(data: string) {
    const argon2 = require('argon2');
    return await argon2.hash(data);
  }

  async verifyHash(subject: string, hash: string, error: HttpException) {
    const argon2 = require('argon2');
    try {
      if (!(await argon2.verify(hash, subject))) {
        throw error;
      }
    } catch (err) {
      throw error;
    }
  }

  async getTokens(userId: number, email: string) {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: process.env.AT_SECRET,
          expiresIn: 60 * 15,
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: process.env.RT_SECRET,
          expiresIn: 60 * 30 * 24 * 7,
        },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}
function data(
  arg0: { where: { id: number; hashedRt: { not: null } } },
  data: any,
  arg2: { hashedRt: null },
) {
  throw new Error('Function not implemented.');
}

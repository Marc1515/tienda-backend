import { PartialType } from '@nestjs/mapped-types';
import { CreateUserDto } from './create-USER.dto';

export class UpdateAuthDto extends PartialType(CreateUserDto) {}

import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUtilityDto } from './dto/create-utility.dto';
import { UpdateUtilityDto } from './dto/update-utility.dto';

@Injectable()
export class UtilityService {
  constructor(private prisma: PrismaService) {}

  async create(createUtilityDto: CreateUtilityDto) {
    return this.prisma.utility.create({
      data: createUtilityDto,
    });
  }

  async findAll() {
    return this.prisma.utility.findMany();
  }

  async findOne(id: string) {
    return this.prisma.utility.findUnique({
      where: { id },
    });
  }

  async update(id: string, updateUtilityDto: UpdateUtilityDto) {
    return this.prisma.utility.update({
      where: { id },
      data: updateUtilityDto,
    });
  }

  async remove(id: string) {
    return this.prisma.utility.delete({
      where: { id },
    });
  }
}